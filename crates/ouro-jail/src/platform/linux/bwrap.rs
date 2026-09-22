//! The bubblewrap plan for the `tool` profile: argv, mount table, and the
//! placeholder mount points an absent protected literal needs.
//!
//! jail-v1 §9.1 and §9.2, north-star §4.3. The plan is data; rendering it is
//! a pure function, so the argv and the mount table the receipt records come
//! from the same structure and cannot disagree.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::fs::{RootSpec, exists_resolved, resolve_runtime_root};
use super::sys::{PathError, cstring_from_os, empty_stat, errno_name, last_errno};

/// Where the jail's own binary is bound inside the sandbox.
pub const JAIL_INSIDE_PATH: &str = "/run/ouro/jail";
/// Where the scratch directory appears inside the sandbox.
pub const SCRATCH_INSIDE_PATH: &str = "/tmp";
// J3-launch begin: the in-sandbox location of vendor state
/// Where vendor state appears inside the sandbox. jail-v1 §9.1 fixes no
/// location; this is beside [`JAIL_INSIDE_PATH`], under the sandbox's own
/// read-only `/run/ouro`, so its parent (the attempt directory) is never
/// visible and no operator grant can shadow it (J3 contract §3.2).
pub const VENDOR_STATE_INSIDE_PATH: &str = "/run/ouro/state";
// J3-launch end

/// The system roots the `tool` profile grants read-only (north-star §4.2).
pub const RUNTIME_ROOTS: [&str; 7] = [
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
];

/// The `/etc` files the `tool` profile grants read-only. `/etc/ld.so.cache` is
/// not in the north star's list but is needed for the dynamic loader to find
/// anything; it is granted when present and recorded in the mount table like
/// every other grant.
pub const ETC_PATHS: [&str; 7] = [
    "/etc/ssl",
    "/etc/resolv.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/localtime",
    "/etc/ld.so.cache",
];

/// Total rendered argv bytes past which the plan is handed over `--args FD`
/// instead of the command line. ARG_MAX is normally 2 MiB; this is the
/// "comfort" bound CONTRACT §3.6 asks for.
pub const ARGS_FD_THRESHOLD: usize = 128 * 1024;

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// The version bubblewrap reports, kept verbatim for the receipt's
/// `backend_version`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BwrapVersion {
    /// The whole line, as printed.
    pub raw: String,
    /// Major component.
    pub major: u32,
    /// Minor component.
    pub minor: u32,
    /// Patch component, zero when not printed.
    pub patch: u32,
}

/// Parse `bubblewrap 0.11.1`.
#[must_use]
pub fn parse_version(line: &str) -> Option<BwrapVersion> {
    let raw = line.trim();
    let number = raw.split_whitespace().last()?;
    let mut parts = number.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some(BwrapVersion {
        raw: raw.to_owned(),
        major,
        minor,
        patch,
    })
}

/// Run `bwrap --version`.
///
/// # Errors
///
/// A failure to run the binary, or output that does not parse.
pub fn bwrap_version(bwrap: &Path) -> io::Result<BwrapVersion> {
    let out = Command::new(bwrap).arg("--version").output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{} --version exited {:?}",
            bwrap.display(),
            out.status.code()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    parse_version(&text).ok_or_else(|| io::Error::other(format!("unparsed version {text:?}")))
}

// ---------------------------------------------------------------------------
// Placeholders
// ---------------------------------------------------------------------------

/// Where a placeholder is mounted from and to.
///
/// The plan needs only these two paths to render its argv; the identity that
/// decides whether the thing may be removed afterwards lives in
/// [`Placeholder`], which is not copyable because it holds an open handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceholderMount {
    /// The empty directory bound over the destination.
    pub source: PathBuf,
    /// The mount point inside the workspace.
    pub destination: PathBuf,
}

/// A mount point created so that an absent protected literal can still be
/// covered by a read-only bind (jail-v1 §9.1: "Root-level protected literals
/// must also be protected when absent").
///
/// Bubblewrap will create a missing destination itself, inside the
/// bind-mounted workspace, and never remove it. Creating it here instead means
/// its exact inode identity and ownership are registered *before use*, which
/// is what the spec requires, and means the cleanup afterwards can tell "the
/// empty directory we made" from "something the run created".
///
/// The registration is a held handle, not a recorded number. A device and
/// inode pair is not an identity across a delete and a recreate: on ext4 the
/// freed inode is handed straight back, so a directory removed and remade
/// under the same name arrives with the same number and a recorded pair
/// matches something this code never created. An open descriptor cannot be
/// fooled that way — the kernel will not free an inode that is still open, so
/// while this handle lives the number cannot be reused, and a name that now
/// resolves to a different inode is visibly a different object.
#[derive(Debug)]
pub struct Placeholder {
    mount: PlaceholderMount,
    /// Device of the destination at registration.
    dev: u64,
    /// Inode of the destination at registration.
    ino: u64,
    /// Owning uid at registration.
    uid: u32,
    /// Permission bits at registration.
    mode: u32,
    /// Creation time, as seconds and nanoseconds, where the filesystem keeps
    /// one. Extra evidence for the receipt, never the check on its own: a
    /// filesystem without birth times would make such a check vacuous.
    birth: Option<(i64, u32)>,
    /// The handle that keeps the registered inode alive, held from creation
    /// to removal. `O_PATH`, so it carries no read or write authority, and
    /// close-on-exec, so no child ever sees it.
    handle: OwnedFd,
}

/// Why a placeholder could not be established.
#[derive(Debug)]
pub enum PlaceholderError {
    /// The destination already exists, so it is a pre-existing object and must
    /// be treated as one. Never removed.
    DestinationExists(PathBuf),
    /// A filesystem call failed.
    Io {
        /// What was being done.
        path: PathBuf,
        /// The errno.
        errno: i32,
    },
    /// A path could not be handed to a syscall.
    Path(PathError),
}

impl fmt::Display for PlaceholderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationExists(p) => {
                write!(f, "{} already exists; it is not a placeholder", p.display())
            }
            Self::Io { path, errno } => {
                write!(f, "{}: {}", path.display(), errno_name(*errno))
            }
            Self::Path(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PlaceholderError {}

/// What became of a placeholder after the tree died.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlaceholderOutcome {
    /// Unchanged and empty: removed.
    Removed(PathBuf),
    /// Already gone; nothing to do.
    AlreadyGone(PathBuf),
    /// Identity, ownership or mode changed: kept, with the reason.
    KeptChanged(PathBuf, String),
    /// Something is inside it: kept.
    KeptNotEmpty(PathBuf),
    /// Removal failed.
    KeptError(PathBuf, i32),
}

impl Placeholder {
    /// Create the empty source directory and the destination mount point, and
    /// register the destination's identity.
    ///
    /// # Errors
    ///
    /// [`PlaceholderError::DestinationExists`] when the destination is already
    /// there — the caller must then treat it as a pre-existing protected
    /// segment — or an I/O errno.
    pub fn create(source: &Path, destination: &Path) -> Result<Self, PlaceholderError> {
        let source_c = cstring_from_os(source.as_os_str()).map_err(PlaceholderError::Path)?;
        let dest_c = cstring_from_os(destination.as_os_str()).map_err(PlaceholderError::Path)?;

        // SAFETY: `source_c` is a NUL-terminated path that outlives the call.
        if unsafe { libc::mkdir(source_c.as_ptr(), 0o700) } != 0 {
            let errno = last_errno();
            if errno != libc::EEXIST {
                return Err(PlaceholderError::Io {
                    path: source.to_owned(),
                    errno,
                });
            }
        }
        // SAFETY: `dest_c` is a NUL-terminated path that outlives the call.
        if unsafe { libc::mkdir(dest_c.as_ptr(), 0o700) } != 0 {
            let errno = last_errno();
            return Err(if errno == libc::EEXIST {
                PlaceholderError::DestinationExists(destination.to_owned())
            } else {
                PlaceholderError::Io {
                    path: destination.to_owned(),
                    errno,
                }
            });
        }

        // The handle is taken immediately, so the identity registered below is
        // one that cannot be handed to another object while this lives.
        // SAFETY: `dest_c` is NUL-terminated and outlives the call. `O_PATH`
        // acquires no I/O authority and `O_NOFOLLOW` refuses a symlink at the
        // final component.
        let handle = unsafe {
            libc::open(
                dest_c.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if handle < 0 {
            return Err(PlaceholderError::Io {
                path: destination.to_owned(),
                errno: last_errno(),
            });
        }
        // SAFETY: `handle` was just opened and is owned here.
        let handle = unsafe { OwnedFd::from_raw_fd(handle) };

        let mut stat = empty_stat();
        // SAFETY: `handle` is live and `stat` is a writable buffer; fstat on
        // an `O_PATH` descriptor is permitted.
        if unsafe { libc::fstat(handle.as_raw_fd(), &raw mut stat) } != 0 {
            return Err(PlaceholderError::Io {
                path: destination.to_owned(),
                errno: last_errno(),
            });
        }
        Ok(Self {
            mount: PlaceholderMount {
                source: source.to_owned(),
                destination: destination.to_owned(),
            },
            dev: stat.st_dev,
            ino: stat.st_ino,
            uid: stat.st_uid,
            mode: stat.st_mode & 0o7777,
            birth: birth_time(&handle),
            handle,
        })
    }

    /// Where this placeholder is mounted from and to.
    #[must_use]
    pub fn mount(&self) -> &PlaceholderMount {
        &self.mount
    }

    /// The empty directory bound over the destination.
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.mount.source
    }

    /// The mount point inside the workspace.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.mount.destination
    }

    /// Device and inode registered at creation.
    #[must_use]
    pub const fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }

    /// The registered creation time, where the filesystem keeps one.
    #[must_use]
    pub const fn birth(&self) -> Option<(i64, u32)> {
        self.birth
    }

    /// Remove the placeholder if it is still the directory that was created,
    /// and still empty.
    ///
    /// jail-v1 §9.1: "remove only unchanged, empty placeholders it created
    /// after tree death. Never remove a pre-existing Git file/directory."
    ///
    /// The question this answers is not "does the name still have the numbers
    /// I wrote down" but "does the name still resolve to the object I am
    /// holding". Those differ exactly where it matters: delete the directory,
    /// make another with the same name, and on ext4 the second one gets the
    /// first one's inode number back. Comparing against the held handle cannot
    /// be fooled, because the inode behind it is not free to be reused.
    ///
    /// Every step works on a descriptor rather than on the name. The parent is
    /// opened once without following a symlink and everything else goes
    /// through it, so a name resolved four times is not four chances for
    /// something else to be standing there by the last one — and the last one
    /// is a deletion.
    #[must_use]
    pub fn remove_if_unchanged(&self) -> PlaceholderOutcome {
        let path = self.mount.destination.clone();
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return PlaceholderOutcome::KeptError(path, libc::EINVAL);
        };
        let Ok(parent_fd) = open_directory(parent) else {
            return PlaceholderOutcome::KeptError(path, last_errno());
        };
        let Ok(name_c) = cstring_from_os(name) else {
            return PlaceholderOutcome::KeptError(path, libc::EINVAL);
        };

        // What this code is holding.
        let mut held = empty_stat();
        // SAFETY: the handle is live and `held` is a writable buffer.
        if unsafe { libc::fstat(self.handle.as_raw_fd(), &raw mut held) } != 0 {
            return PlaceholderOutcome::KeptError(path, last_errno());
        }

        // What the name refers to now.
        let mut now = empty_stat();
        // SAFETY: `parent_fd` is a live directory descriptor, `name_c` is
        // NUL-terminated, and `AT_SYMLINK_NOFOLLOW` stats the entry itself.
        if unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                name_c.as_ptr(),
                &raw mut now,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let errno = last_errno();
            return match errno {
                libc::ENOENT => PlaceholderOutcome::AlreadyGone(path),
                other => PlaceholderOutcome::KeptError(path, other),
            };
        }
        if now.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return PlaceholderOutcome::KeptChanged(path, "no longer a directory".to_owned());
        }
        if (now.st_dev, now.st_ino) != (held.st_dev, held.st_ino) {
            return PlaceholderOutcome::KeptChanged(
                path,
                format!(
                    "identity changed from {}:{} to {}:{}",
                    held.st_dev, held.st_ino, now.st_dev, now.st_ino
                ),
            );
        }
        if now.st_uid != self.uid {
            return PlaceholderOutcome::KeptChanged(path, "owner changed".to_owned());
        }
        if now.st_mode & 0o7777 != self.mode {
            return PlaceholderOutcome::KeptChanged(path, "permissions changed".to_owned());
        }

        // Emptiness, through a fresh descriptor for the same entry — and that
        // descriptor is checked against the handle too, so the window between
        // the stat above and this open cannot be used to swap the object.
        let entry = match open_entry(&parent_fd, &name_c) {
            Ok(entry) => entry,
            Err(libc::ENOENT) => return PlaceholderOutcome::AlreadyGone(path),
            Err(errno @ (libc::ENOTDIR | libc::ELOOP)) => {
                let _ = errno;
                return PlaceholderOutcome::KeptChanged(path, "no longer a directory".to_owned());
            }
            Err(errno) => return PlaceholderOutcome::KeptError(path, errno),
        };
        let mut opened = empty_stat();
        // SAFETY: `entry` is live and `opened` is a writable buffer.
        if unsafe { libc::fstat(entry.as_raw_fd(), &raw mut opened) } != 0 {
            return PlaceholderOutcome::KeptError(path, last_errno());
        }
        if (opened.st_dev, opened.st_ino) != (held.st_dev, held.st_ino) {
            return PlaceholderOutcome::KeptChanged(
                path,
                "the entry was replaced while it was being checked".to_owned(),
            );
        }
        match directory_is_empty(&entry) {
            Ok(true) => {}
            Ok(false) => return PlaceholderOutcome::KeptNotEmpty(path),
            Err(errno) => return PlaceholderOutcome::KeptError(path, errno),
        }
        drop(entry);

        // SAFETY: `parent_fd` is live and `name_c` is NUL-terminated;
        // AT_REMOVEDIR removes the directory entry the checks above described.
        if unsafe { libc::unlinkat(parent_fd.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR) }
            != 0
        {
            return PlaceholderOutcome::KeptError(path, last_errno());
        }
        let _ = std::fs::remove_dir(&self.mount.source);
        PlaceholderOutcome::Removed(path)
    }
}

/// Open one entry of a directory as a directory, without following a symlink.
fn open_entry(parent: &OwnedFd, name: &std::ffi::CStr) -> Result<OwnedFd, i32> {
    // SAFETY: `parent` is a live directory descriptor and `name` is a
    // NUL-terminated name valid for the call.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: `fd` was just opened and is owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The creation time of an open object, where the filesystem records one.
///
/// `None` on a filesystem that keeps no birth time, which is why this is
/// recorded as evidence beside the handle rather than relied on: a check that
/// silently passes wherever the fact is absent is not a check.
fn birth_time(handle: &OwnedFd) -> Option<(i64, u32)> {
    let mut buffer: libc::statx = unsafe { std::mem::zeroed() };
    let empty = c"";
    // SAFETY: `handle` is live, `empty` is a NUL-terminated empty string and
    // `AT_EMPTY_PATH` makes statx describe the descriptor itself, which is
    // permitted for an `O_PATH` one. `buffer` is a live writable statx.
    let rc = unsafe {
        libc::statx(
            handle.as_raw_fd(),
            empty.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_BTIME,
            &raw mut buffer,
        )
    };
    if rc != 0 || buffer.stx_mask & libc::STATX_BTIME == 0 {
        return None;
    }
    Some((buffer.stx_btime.tv_sec, buffer.stx_btime.tv_nsec))
}

/// Open a directory without following a symlink at its final component.
fn open_directory(path: &Path) -> Result<OwnedFd, i32> {
    let c = cstring_from_os(path.as_os_str()).map_err(|_| libc::EINVAL)?;
    // SAFETY: `c` is a NUL-terminated path that outlives the call.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: `fd` was just opened and is owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Whether an open directory has any entry besides `.` and `..`.
fn directory_is_empty(dir: &OwnedFd) -> Result<bool, i32> {
    // `fdopendir` takes ownership of what it is given, so it gets a duplicate.
    // SAFETY: `dir` is a live directory descriptor.
    let duplicate = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(last_errno());
    }
    // SAFETY: `duplicate` is a fresh directory descriptor; closedir releases
    // it exactly once.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let errno = last_errno();
        // SAFETY: fdopendir failed, so the descriptor is still ours to close.
        unsafe { libc::close(duplicate) };
        return Err(errno);
    }
    let mut empty = true;
    let mut failure = None;
    loop {
        // SAFETY: errno is this thread's own.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `stream` is the DIR* just created; the returned pointer is
        // valid until the next call on the same stream.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let errno = last_errno();
            if errno != 0 {
                failure = Some(errno);
            }
            break;
        }
        // SAFETY: `entry` is non-null and `d_name` is a NUL-terminated array
        // inside it.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes != b"." && bytes != b".." {
            empty = false;
            break;
        }
    }
    // SAFETY: `stream` was created above and is closed exactly once here.
    unsafe { libc::closedir(stream) };
    match failure {
        Some(errno) => Err(errno),
        None => Ok(empty),
    }
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// One row of the mount table the receipt records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountRow {
    /// `ro-bind`, `bind`, `symlink`, `proc`, `dev`, `cwd`, `tmpfs-mask` or
    /// `placeholder`.
    pub kind: &'static str,
    /// The host source, or the symlink target, or nothing for a mount with no
    /// source (`proc`, `dev`, `cwd`, `tmpfs-mask`).
    pub source: Option<OsString>,
    /// The path inside the sandbox.
    pub destination: OsString,
}

/// One protected segment in the plan: the source path to bind read-only over
/// itself, and the fixed descriptor number its pinned `O_PATH` handle was
/// installed at, when it has one.
#[derive(Clone, Debug)]
pub struct ProtectedBind {
    /// The source path, as scanned.
    pub source: PathBuf,
    /// Descriptor number, valid in the bubblewrap process, holding the pinned
    /// source object (`--ro-bind-fd`); `None` binds by path.
    pub fd: Option<RawFd>,
}
/// Everything needed to build a bubblewrap invocation.
#[derive(Clone, Debug)]
pub struct BwrapPlan {
    /// Path to the `bwrap` binary.
    pub bwrap: PathBuf,
    /// System roots, already classified into binds and merged-`/usr` symlinks.
    pub roots: Vec<RootSpec>,
    /// `/etc` grants that exist on this host.
    pub etc_paths: Vec<PathBuf>,
    /// The writable workspace, mounted at the same path inside.
    pub workspace: PathBuf,
    /// None exposes only an empty working directory, never undeclared inputs.
    /// Some(true) is writable; Some(false) is read-only.
    pub workspace_access: Option<bool>,
    /// The scratch directory, mounted at `/tmp` inside.
    pub scratch: PathBuf,
    /// Source descriptors for each row of `mount_table`, populated by preparation.
    /// Each mount owns a distinct descriptor: bubblewrap closes it after binding.
    pub mount_fds: Vec<Option<RawFd>>,
    /// Environment to set after `--clearenv`.
    pub env: Vec<(OsString, OsString)>,
    /// Existing protected segments, each bound read-only over itself. A pin
    /// whose `O_PATH` handle was handed to the spawn map is bound by
    /// descriptor (`--ro-bind-fd`), which cannot be redirected by a path
    /// swap between validation and mount (§9.1); the rest are bound by path
    /// and re-verified at handoff.
    pub protected: Vec<ProtectedBind>,
    /// Extra read-only binds with a destination of their own, used by the
    /// doctor probes and by operator `--ro` grants (§6.1).
    pub extra_ro_binds: Vec<(PathBuf, PathBuf)>,
    /// Extra writable binds from operator `--rw` grants, applied after the
    /// workspace bind so a grant inside it stays writable (§6.1).
    pub extra_rw_binds: Vec<(PathBuf, PathBuf)>,
    /// Denied subtrees, masked with a `tmpfs` over the path after every
    /// other mount (north-star §4.3: denied subtrees inside visible parents
    /// are "absent or masked by the backend").
    pub masked: Vec<PathBuf>,
    /// Placeholders for absent root-level literals.
    pub placeholders: Vec<PlaceholderMount>,
    /// The jail binary to bind at [`JAIL_INSIDE_PATH`].
    pub jail_exe: PathBuf,
    /// Descriptor carrying the seccomp program.
    pub seccomp_fd: Option<RawFd>,
    /// Descriptor bubblewrap writes its own JSON status to.
    pub json_status_fd: Option<RawFd>,
    /// Descriptor to read the argument list from, when the list is long.
    pub args_fd: Option<RawFd>,
    /// Force the `--args` path even for a short list, so tests can exercise it.
    pub force_args_fd: bool,
    /// The command inside the sandbox, normally
    /// `/run/ouro/jail __launch ... -- PROGRAM ARG...`.
    pub inner: Vec<OsString>,
    // J3-launch begin: vendor state and bind_ro credentials, bound by
    // descriptor only (§9.1, §12)
    /// The host vendor-state directory, for the mount table and diagnostics.
    /// It is never bound by this path: only by [`BwrapPlan::vendor_state_fd`].
    pub vendor_state: Option<PathBuf>,
    /// Descriptor number, valid in the bubblewrap process, of the
    /// vendor-state directory the supervisor created (`--bind-fd`).
    pub vendor_state_fd: Option<RawFd>,
    /// `bind_ro` credential views: each exact source object's descriptor and
    /// its destination under [`VENDOR_STATE_INSIDE_PATH`] (`--ro-bind-fd`).
    pub credential_binds: Vec<CredentialBind>,
    // J3-launch end
}

// J3-launch begin: one bind_ro credential view
/// One read-only credential view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialBind {
    /// Descriptor number, valid in the bubblewrap process, of the exact
    /// source object; `None` until preparation assigns it, and a plan with a
    /// `None` here refuses to render rather than bind by path.
    pub fd: Option<RawFd>,
    /// The destination inside the sandbox.
    pub destination: PathBuf,
}
// J3-launch end

/// Why a plan cannot be rendered.
#[derive(Debug)]
pub enum PlanError {
    /// A path that must be absolute is not.
    NotAbsolute(&'static str, PathBuf),
    /// A path cannot be passed to a syscall.
    Path(&'static str, PathError),
    /// The plan asks for `--args` but no descriptor was provided.
    ArgsFdMissing,
    /// There is no command to run.
    NoCommand,
    // J3-launch begin: a staged object is bound by descriptor or not at all
    /// A vendor-state or credential mount has no descriptor.
    StagedFdMissing(&'static str),
    // J3-launch end
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute(what, p) => {
                write!(f, "{what} must be an absolute path, got {}", p.display())
            }
            Self::Path(what, e) => write!(f, "{what}: {e}"),
            Self::ArgsFdMissing => write!(f, "the argument list needs --args but no fd was given"),
            Self::NoCommand => write!(f, "the plan has no command to run"),
            // J3-launch begin
            Self::StagedFdMissing(what) => {
                write!(
                    f,
                    "the {what} mount has no descriptor; it is never bound by path"
                )
            } // J3-launch end
        }
    }
}

impl std::error::Error for PlanError {}

/// A rendered invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// The argv to execute, including `bwrap` itself.
    pub argv: Vec<OsString>,
    /// When present, the NUL-separated argument list to write to
    /// [`BwrapPlan::args_fd`]; `argv` is then just `bwrap --args FD`.
    pub args_payload: Option<Vec<u8>>,
}

impl BwrapPlan {
    /// A `tool` plan with this host's runtime roots and `/etc` grants filled
    /// in, and the environment the profile allows.
    #[must_use]
    pub fn tool(workspace: &Path, scratch: &Path, jail_exe: &Path) -> Self {
        let roots = RUNTIME_ROOTS
            .iter()
            .filter_map(|p| resolve_runtime_root(Path::new(p)))
            .collect();
        let etc_paths = ETC_PATHS
            .iter()
            .map(Path::new)
            .filter(|p| exists_resolved(p))
            .map(Path::to_path_buf)
            .collect();
        Self {
            bwrap: PathBuf::from("bwrap"),
            roots,
            etc_paths,
            workspace: workspace.to_owned(),
            workspace_access: Some(true),
            scratch: scratch.to_owned(),
            mount_fds: Vec::new(),
            env: vec![
                (
                    OsString::from("PATH"),
                    OsString::from("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
                ),
                (
                    OsString::from("TMPDIR"),
                    OsString::from(SCRATCH_INSIDE_PATH),
                ),
            ],
            protected: Vec::new(),
            extra_ro_binds: Vec::new(),
            extra_rw_binds: Vec::new(),
            masked: Vec::new(),
            placeholders: Vec::new(),
            jail_exe: jail_exe.to_owned(),
            seccomp_fd: None,
            json_status_fd: None,
            args_fd: None,
            force_args_fd: false,
            inner: Vec::new(),
            // J3-launch begin
            vendor_state: None,
            vendor_state_fd: None,
            credential_binds: Vec::new(),
            // J3-launch end
        }
    }

    /// The mount table, in the order the mounts are applied.
    #[must_use]
    pub fn mount_table(&self) -> Vec<MountRow> {
        let mut rows = Vec::new();
        for root in &self.roots {
            match root {
                RootSpec::RoBind(p) => rows.push(MountRow {
                    kind: "ro-bind",
                    source: Some(p.as_os_str().to_owned()),
                    destination: p.as_os_str().to_owned(),
                }),
                RootSpec::Symlink { path, target } => rows.push(MountRow {
                    kind: "symlink",
                    source: Some(target.as_os_str().to_owned()),
                    destination: path.as_os_str().to_owned(),
                }),
            }
        }
        for etc in &self.etc_paths {
            rows.push(MountRow {
                kind: "ro-bind",
                source: Some(etc.as_os_str().to_owned()),
                destination: etc.as_os_str().to_owned(),
            });
        }
        rows.push(MountRow {
            kind: "proc",
            source: None,
            destination: OsString::from("/proc"),
        });
        rows.push(MountRow {
            kind: "dev",
            source: None,
            destination: OsString::from("/dev"),
        });
        // The base roots, ancestors before descendants. The workspace is one
        // of them in whichever mode the plan grants it: a read-only workspace
        // sits under any writable grant inside it rather than covering it,
        // and an ungranted one is an empty tmpfs mounted after a scratch at
        // /tmp that would otherwise hide it, then sealed read-only by the
        // argv once every grant beneath it is in place.
        let mut base: Vec<(&'static str, Option<PathBuf>, PathBuf)> = self
            .extra_rw_binds
            .iter()
            .map(|(source, destination)| ("bind", Some(source.clone()), destination.clone()))
            .collect();
        base.push((
            "bind",
            Some(self.scratch.clone()),
            PathBuf::from(SCRATCH_INSIDE_PATH),
        ));
        base.push(match self.workspace_access {
            Some(true) => ("bind", Some(self.workspace.clone()), self.workspace.clone()),
            Some(false) => (
                "ro-bind",
                Some(self.workspace.clone()),
                self.workspace.clone(),
            ),
            None => ("cwd", None, self.workspace.clone()),
        });
        base.sort_by_key(|(_, _, destination)| destination.components().count());
        for (kind, source, destination) in base {
            rows.push(MountRow {
                kind,
                source: source.map(PathBuf::into_os_string),
                destination: destination.into_os_string(),
            });
        }
        let mut readonly = self.extra_ro_binds.clone();
        readonly.sort_by_key(|(_, destination)| destination.components().count());
        for (source, destination) in readonly {
            rows.push(MountRow {
                kind: "ro-bind",
                source: Some(source.into_os_string()),
                destination: destination.into_os_string(),
            });
        }
        for protected in &self.protected {
            rows.push(MountRow {
                kind: if protected.fd.is_some() {
                    "ro-bind-fd"
                } else {
                    "ro-bind"
                },
                source: Some(protected.source.as_os_str().to_owned()),
                destination: protected.source.as_os_str().to_owned(),
            });
        }
        for placeholder in &self.placeholders {
            rows.push(MountRow {
                kind: "placeholder",
                source: Some(placeholder.source.as_os_str().to_owned()),
                destination: placeholder.destination.as_os_str().to_owned(),
            });
        }
        // J3-launch begin: vendor state, then the credential views inside it.
        // After every operator grant, so no `--ro`/`--rw` of an ancestor of
        // `/run/ouro` can shadow them; before the masks, like the jail binary.
        if let Some(host) = &self.vendor_state {
            rows.push(MountRow {
                kind: "vendor-state",
                source: Some(host.as_os_str().to_owned()),
                destination: OsString::from(VENDOR_STATE_INSIDE_PATH),
            });
        }
        let mut views: Vec<&CredentialBind> = self.credential_binds.iter().collect();
        views.sort_by_key(|view| view.destination.components().count());
        for view in views {
            rows.push(MountRow {
                kind: "credential",
                // Never the source path: it is private operational state.
                source: None,
                destination: view.destination.as_os_str().to_owned(),
            });
        }
        // J3-launch end
        rows.push(MountRow {
            kind: "ro-bind",
            source: Some(self.jail_exe.as_os_str().to_owned()),
            destination: OsString::from(JAIL_INSIDE_PATH),
        });
        let mut masks = self.masked.clone();
        masks.sort_by_key(|path| path.components().count());
        for path in masks {
            rows.push(MountRow {
                kind: "tmpfs-mask",
                source: None,
                destination: path.into_os_string(),
            });
        }
        rows
    }

    /// Render the invocation.
    ///
    /// # Errors
    ///
    /// [`PlanError`] for a relative path, an unusable path, a missing command,
    /// or a long list with no `--args` descriptor.
    pub fn render(&self) -> Result<Rendered, PlanError> {
        if self.inner.is_empty() {
            return Err(PlanError::NoCommand);
        }
        for (what, path) in [
            ("workspace", &self.workspace),
            ("scratch", &self.scratch),
            ("jail binary", &self.jail_exe),
        ] {
            if !path.is_absolute() {
                return Err(PlanError::NotAbsolute(what, path.clone()));
            }
            cstring_from_os(path.as_os_str()).map_err(|e| PlanError::Path(what, e))?;
        }

        // J3-launch begin: every staged mount has its descriptor
        if self.vendor_state.is_some() && self.vendor_state_fd.is_none() {
            return Err(PlanError::StagedFdMissing("vendor-state"));
        }
        if self.credential_binds.iter().any(|view| view.fd.is_none()) {
            return Err(PlanError::StagedFdMissing("credential"));
        }
        // J3-launch end
        let mut tail: Vec<OsString> = Vec::new();
        // Scoped so the closure's borrow of `tail` ends before the length of
        // the rendered list is measured.
        {
            let mut push = |parts: &[&OsStr]| {
                for part in parts {
                    tail.push((*part).to_owned());
                }
            };

            for flag in [
                "--unshare-user",
                "--unshare-pid",
                "--unshare-net",
                "--unshare-ipc",
                "--unshare-uts",
                // §9.1: no host namespace handle reaches the child. Without
                // this the child reads the supervisor's own cgroup path out
                // of /proc/self/cgroup, which names the operator's session.
                "--unshare-cgroup",
                "--die-with-parent",
                "--new-session",
                "--clearenv",
            ] {
                push(&[OsStr::new(flag)]);
            }
            for (key, value) in &self.env {
                push(&[OsStr::new("--setenv"), key, value]);
            }
            for (index, row) in self.mount_table().iter().enumerate() {
                let fd = self.mount_fds.get(index).copied().flatten().or_else(|| {
                    self.protected
                        .iter()
                        .find(|p| p.source.as_os_str() == row.destination)
                        .and_then(|p| p.fd)
                });
                // J3-launch begin: staged objects carry their own descriptor
                let fd = match row.kind {
                    "vendor-state" => self.vendor_state_fd,
                    "credential" => self
                        .credential_binds
                        .iter()
                        .find(|view| view.destination.as_os_str() == row.destination)
                        .and_then(|view| view.fd),
                    _ => fd,
                };
                // J3-launch end
                let flag = match row.kind {
                    "bind" if fd.is_some() => "--bind-fd",
                    "ro-bind" | "ro-bind-fd" | "placeholder" if fd.is_some() => "--ro-bind-fd",
                    "bind" => "--bind",
                    "ro-bind" | "ro-bind-fd" | "placeholder" => "--ro-bind",
                    "symlink" => "--symlink",
                    "tmpfs-mask" => "--tmpfs",
                    "proc" => "--proc",
                    "dev" => "--dev",
                    "cwd" => "--tmpfs",
                    // J3-launch begin: checked above to have a descriptor
                    "vendor-state" => "--bind-fd",
                    "credential" => "--ro-bind-fd",
                    // J3-launch end
                    _ => unreachable!("mount table kind"),
                };
                if let Some(fd) = fd {
                    push(&[
                        OsStr::new(flag),
                        OsStr::new(&fd.to_string()),
                        &row.destination,
                    ]);
                } else if let Some(source) = &row.source {
                    push(&[OsStr::new(flag), source, &row.destination]);
                } else {
                    push(&[OsStr::new(flag), &row.destination]);
                }
            }
            if self.workspace_access.is_none() {
                // Every grant inside the empty working directory is mounted
                // by now; seal it before the root.
                push(&[OsStr::new("--remount-ro"), self.workspace.as_os_str()]);
            }
            push(&[OsStr::new("--remount-ro"), OsStr::new("/")]);
            push(&[OsStr::new("--chdir"), self.workspace.as_os_str()]);
            if let Some(fd) = self.seccomp_fd {
                push(&[OsStr::new("--seccomp"), OsStr::new(&fd.to_string())]);
            }
            if let Some(fd) = self.json_status_fd {
                push(&[OsStr::new("--json-status-fd"), OsStr::new(&fd.to_string())]);
            }
        }
        let size: usize = tail
            .iter()
            .chain(self.inner.iter())
            .map(|part| part.as_bytes().len() + 1)
            .sum();

        if self.force_args_fd || size > ARGS_FD_THRESHOLD {
            let fd = self.args_fd.ok_or(PlanError::ArgsFdMissing)?;
            // Measured on bubblewrap 0.11.1: `--args FD` supplies options
            // only. A command inside the file leaves bubblewrap with nothing
            // to run and it exits with its usage message. The command stays on
            // the command line, after the `--` separator.
            let mut payload = Vec::with_capacity(size);
            for part in &tail {
                payload.extend_from_slice(part.as_bytes());
                payload.push(0);
            }
            let mut argv = vec![
                self.bwrap.as_os_str().to_owned(),
                OsString::from("--args"),
                OsString::from(fd.to_string()),
                OsString::from("--"),
            ];
            argv.extend(self.inner.iter().cloned());
            return Ok(Rendered {
                argv,
                args_payload: Some(payload),
            });
        }

        tail.push(OsString::from("--"));
        let mut argv = Vec::with_capacity(tail.len() + self.inner.len() + 1);
        argv.push(self.bwrap.as_os_str().to_owned());
        argv.extend(tail);
        argv.extend(self.inner.iter().cloned());
        Ok(Rendered {
            argv,
            args_payload: None,
        })
    }
}

/// Build the inner command line: the jail's own binary, re-executed inside.
#[must_use]
pub fn inner_launch_command(
    release_fd: RawFd,
    error_fd: RawFd,
    narrow: bool,
    target: &[OsString],
) -> Vec<OsString> {
    let mut out = vec![
        OsString::from(JAIL_INSIDE_PATH),
        OsString::from(super::launch::SUBCOMMAND),
        OsString::from("--release-fd"),
        OsString::from(release_fd.to_string()),
        OsString::from("--error-fd"),
        OsString::from(error_fd.to_string()),
    ];
    if narrow {
        out.push(OsString::from("--narrow"));
    }
    out.push(OsString::from("--"));
    out.extend(target.iter().cloned());
    out
}

/// One document bubblewrap writes to `--json-status-fd`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BwrapStatus {
    /// Host pid of the namespace init, when reported.
    pub child_pid: Option<libc::pid_t>,
    /// Exit code of the inner command, when reported.
    pub exit_code: Option<i32>,
}

/// Parse bubblewrap's JSON status stream.
///
/// The documents are flat objects with integer values, so this reads the two
/// keys the supervisor needs without pulling a JSON parser into the platform
/// layer. Anything it does not recognise is left `None` rather than guessed.
#[must_use]
pub fn parse_json_status(raw: &str) -> BwrapStatus {
    fn integer_after(raw: &str, key: &str) -> Option<i64> {
        let at = raw.find(&format!("\"{key}\""))?;
        let rest = &raw[at + key.len() + 2..];
        let colon = rest.find(':')?;
        let value: String = rest[colon + 1..]
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        value.parse().ok()
    }
    BwrapStatus {
        child_pid: integer_after(raw, "child-pid").and_then(|v| libc::pid_t::try_from(v).ok()),
        exit_code: integer_after(raw, "exit-code").and_then(|v| i32::try_from(v).ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse() {
        let v = parse_version("bubblewrap 0.11.1\n").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (0, 11, 1));
        assert_eq!(v.raw, "bubblewrap 0.11.1");
        assert_eq!(parse_version("bubblewrap 1.0").unwrap().patch, 0);
        assert!(parse_version("").is_none());
        assert!(parse_version("bubblewrap unknown").is_none());
    }

    #[test]
    fn json_status_documents_parse() {
        let raw = r#"{"child-pid": 12574, "mnt-namespace": 4026533229}
{"exit-code": 7}"#;
        assert_eq!(
            parse_json_status(raw),
            BwrapStatus {
                child_pid: Some(12574),
                exit_code: Some(7),
            }
        );
        assert_eq!(parse_json_status("{}"), BwrapStatus::default());
    }

    fn sample_plan() -> BwrapPlan {
        let mut plan = BwrapPlan::tool(
            Path::new("/work/space"),
            Path::new("/scratch/dir"),
            Path::new("/usr/local/bin/ouro-jail"),
        );
        plan.roots = vec![
            RootSpec::RoBind(PathBuf::from("/usr")),
            RootSpec::Symlink {
                path: PathBuf::from("/bin"),
                target: PathBuf::from("usr/bin"),
            },
        ];
        plan.etc_paths = vec![PathBuf::from("/etc/passwd")];
        plan.protected = vec![ProtectedBind {
            source: PathBuf::from("/work/space/.git"),
            fd: None,
        }];
        plan.seccomp_fd = Some(10);
        plan.json_status_fd = Some(11);
        plan.inner = inner_launch_command(12, 13, true, &[OsString::from("/bin/true")]);
        plan
    }

    #[test]
    fn the_argv_has_the_profile_the_north_star_describes() {
        let rendered = sample_plan().render().unwrap();
        let text: Vec<String> = rendered
            .argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for flag in [
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            // §9.1: no host namespace handle reaches the child. Without this
            // the child reads the supervisor's own cgroup path out of
            // /proc/self/cgroup, which names the operator's session.
            "--unshare-cgroup",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ] {
            assert!(text.contains(&flag.to_owned()), "missing {flag}");
        }
        let joined = text.join(" ");
        assert!(joined.contains("--symlink usr/bin /bin"));
        assert!(joined.contains("--ro-bind /usr /usr"));
        assert!(joined.contains("--bind /work/space /work/space"));
        assert!(joined.contains("--bind /scratch/dir /tmp"));
        assert!(joined.contains("--ro-bind /work/space/.git /work/space/.git"));
        assert!(joined.contains("--ro-bind /usr/local/bin/ouro-jail /run/ouro/jail"));
        assert!(joined.contains("--chdir /work/space"));
        assert!(joined.contains("--seccomp 10"));
        assert!(joined.contains("--json-status-fd 11"));
        assert!(joined.contains("--proc /proc --dev /dev"));
        assert!(joined.ends_with(
            "-- /run/ouro/jail __launch --release-fd 12 --error-fd 13 --narrow -- /bin/true"
        ));
        assert!(rendered.args_payload.is_none());
    }

    #[test]
    fn the_scratch_becomes_tmpdir() {
        let plan = sample_plan();
        let rendered = plan.render().unwrap();
        let text = rendered
            .argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("--setenv TMPDIR /tmp"));
    }

    #[test]
    fn a_writable_parent_never_hides_readonly_children_or_masks() {
        let mut plan = sample_plan();
        plan.extra_rw_binds
            .push(("/external".into(), "/external".into()));
        plan.extra_rw_binds
            .push(("/external/deep".into(), "/external/deep".into()));
        plan.extra_ro_binds
            .push(("/external/secrets".into(), "/external/secrets".into()));
        plan.masked.push("/external/secrets/hidden".into());
        let rows = plan.mount_table();
        let index = |path: &str| rows.iter().position(|row| row.destination == path).unwrap();
        assert!(index("/external") < index("/external/deep"));
        assert!(index("/external") < index("/external/secrets"));
        assert!(index("/external/secrets") < index("/external/secrets/hidden"));
        let rendered = plan.render().unwrap();
        let position = |path: &str| rendered.argv.iter().position(|arg| arg == path).unwrap();
        assert!(position("/external") < position("/external/secrets"));
        assert!(position("/external/secrets") < position("/external/secrets/hidden"));
    }

    fn argv_text(plan: &BwrapPlan) -> String {
        let mut text = plan
            .render()
            .unwrap()
            .argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        text.push(' ');
        text
    }

    #[test]
    fn the_root_is_sealed_after_every_mount_and_before_chdir() {
        let text = argv_text(&sample_plan());
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("missing {needle}"))
        };
        assert!(at("--ro-bind /usr/local/bin/ouro-jail /run/ouro/jail ") < at("--remount-ro / "));
        assert!(at("--remount-ro / ") < at("--chdir /work/space "));
        assert!(!text.contains("--remount-ro /work/space "));
    }

    #[test]
    fn an_ungranted_workspace_is_a_sealed_empty_tmpfs_above_scratch() {
        let mut plan = sample_plan();
        plan.workspace = PathBuf::from("/tmp/work/space");
        plan.workspace_access = None;
        plan.protected.clear();
        plan.extra_ro_binds.push((
            PathBuf::from("/tmp/work/space/input"),
            PathBuf::from("/tmp/work/space/input"),
        ));
        let rows = plan.mount_table();
        let index = |path: &str| rows.iter().position(|row| row.destination == path).unwrap();
        assert!(index("/tmp") < index("/tmp/work/space"));
        assert!(index("/tmp/work/space") < index("/tmp/work/space/input"));
        assert_eq!(rows[index("/tmp/work/space")].kind, "cwd");
        assert_eq!(rows[index("/tmp/work/space")].source, None);
        let text = argv_text(&plan);
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("missing {needle}"))
        };
        assert!(at("--bind /scratch/dir /tmp ") < at("--tmpfs /tmp/work/space "));
        assert!(at("--tmpfs /tmp/work/space ") < at("--ro-bind /tmp/work/space/input "));
        assert!(at("--ro-bind /tmp/work/space/input ") < at("--remount-ro /tmp/work/space "));
        assert!(at("--remount-ro /tmp/work/space ") < at("--remount-ro / "));
        assert!(at("--remount-ro / ") < at("--chdir /tmp/work/space "));
        assert!(!text.contains("--bind /tmp/work/space /tmp/work/space "));
        assert!(!text.contains("--dir "));
    }

    #[test]
    fn a_read_only_workspace_sits_under_writable_grants_inside_it() {
        let mut plan = sample_plan();
        plan.workspace_access = Some(false);
        plan.protected.clear();
        plan.extra_rw_binds.push((
            PathBuf::from("/work/space/out"),
            PathBuf::from("/work/space/out"),
        ));
        let rows = plan.mount_table();
        let index = |path: &str| rows.iter().position(|row| row.destination == path).unwrap();
        assert_eq!(rows[index("/work/space")].kind, "ro-bind");
        assert_eq!(rows[index("/work/space/out")].kind, "bind");
        assert!(index("/work/space") < index("/work/space/out"));
        let text = argv_text(&plan);
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("missing {needle}"))
        };
        assert!(
            at("--ro-bind /work/space /work/space ")
                < at("--bind /work/space/out /work/space/out ")
        );
        assert!(!text.contains("--remount-ro /work/space "));
    }

    #[test]
    fn a_long_list_moves_to_the_args_descriptor() {
        let mut plan = sample_plan();
        plan.args_fd = Some(14);
        plan.force_args_fd = true;
        let rendered = plan.render().unwrap();
        // The command stays on the command line: bubblewrap 0.11.1 takes only
        // options from the descriptor.
        assert_eq!(rendered.argv[0], OsString::from("bwrap"));
        assert_eq!(rendered.argv[1], OsString::from("--args"));
        assert_eq!(rendered.argv[2], OsString::from("14"));
        assert_eq!(rendered.argv[3], OsString::from("--"));
        assert_eq!(rendered.argv[4], OsString::from("/run/ouro/jail"));
        let payload = rendered.args_payload.unwrap();
        let parts: Vec<&[u8]> = payload.split(|b| *b == 0).collect();
        assert_eq!(parts[0], b"--unshare-user");
        assert!(
            !parts.iter().any(|p| *p == b"__launch"),
            "the command must not be in the arguments file"
        );
        assert!(
            !parts.iter().any(|p| *p == b"--"),
            "the separator belongs on the command line"
        );
        // The last option is the one the plan emits last.
        assert_eq!(parts[parts.len() - 2], b"11");
        // Splitting on NUL leaves one empty tail after the final terminator.
        assert_eq!(parts.last().unwrap(), b"");
    }

    #[test]
    fn a_long_list_without_a_descriptor_refuses() {
        let mut plan = sample_plan();
        plan.force_args_fd = true;
        assert!(matches!(plan.render(), Err(PlanError::ArgsFdMissing)));
    }

    #[test]
    fn a_relative_workspace_refuses() {
        let mut plan = sample_plan();
        plan.workspace = PathBuf::from("space");
        assert!(matches!(
            plan.render(),
            Err(PlanError::NotAbsolute("workspace", _))
        ));
    }

    #[test]
    fn a_plan_with_no_command_refuses() {
        let mut plan = sample_plan();
        plan.inner.clear();
        assert!(matches!(plan.render(), Err(PlanError::NoCommand)));
    }

    #[test]
    fn the_mount_table_lists_every_grant_the_argv_makes() {
        let plan = sample_plan();
        let rows = plan.mount_table();
        let destinations: Vec<String> = rows
            .iter()
            .map(|r| r.destination.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            destinations,
            vec![
                "/usr",
                "/bin",
                "/etc/passwd",
                "/proc",
                "/dev",
                "/tmp",
                "/work/space",
                "/work/space/.git",
                "/run/ouro/jail",
            ]
        );
        assert_eq!(rows[1].kind, "symlink");
        assert_eq!(rows[1].source.as_deref(), Some(OsStr::new("usr/bin")));
    }

    #[test]
    fn a_path_with_an_interior_nul_refuses() {
        use std::os::unix::ffi::OsStrExt as _;
        let mut plan = sample_plan();
        plan.workspace = PathBuf::from(OsStr::from_bytes(b"/work\0space"));
        assert!(matches!(
            plan.render(),
            Err(PlanError::Path("workspace", _))
        ));
    }
    // J3-launch begin: staged mounts render by descriptor or not at all
    #[test]
    fn staged_vendor_state_and_views_render_by_descriptor_after_every_grant() {
        let mut plan = sample_plan();
        plan.extra_ro_binds = vec![(PathBuf::from("/run"), PathBuf::from("/run"))];
        plan.vendor_state = Some(PathBuf::from("/data/attempts/a/vendor-state"));
        plan.vendor_state_fd = Some(16);
        plan.credential_binds = vec![CredentialBind {
            fd: Some(30),
            destination: PathBuf::from("/run/ouro/state/conf/c.toml"),
        }];
        let argv: Vec<String> = plan
            .render()
            .unwrap()
            .argv
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let at = |needle: &[&str]| {
            argv.windows(needle.len())
                .position(|window| window == needle)
                .unwrap_or_else(|| panic!("{needle:?} in {argv:?}"))
        };
        let vendor = at(&["--bind-fd", "16", VENDOR_STATE_INSIDE_PATH]);
        let view = at(&["--ro-bind-fd", "30", "/run/ouro/state/conf/c.toml"]);
        let grant = at(&["--ro-bind", "/run", "/run"]);
        assert!(grant < vendor && vendor < view, "{argv:?}");
        assert!(
            !argv
                .iter()
                .any(|arg| arg == "/data/attempts/a/vendor-state"),
            "the host path is never a bind source"
        );
    }

    #[test]
    fn a_staged_mount_without_a_descriptor_refuses_to_render() {
        let mut plan = sample_plan();
        plan.vendor_state = Some(PathBuf::from("/data/attempts/a/vendor-state"));
        assert!(matches!(
            plan.render(),
            Err(PlanError::StagedFdMissing("vendor-state"))
        ));
        plan.vendor_state_fd = Some(16);
        plan.credential_binds = vec![CredentialBind {
            fd: None,
            destination: PathBuf::from("/run/ouro/state/c"),
        }];
        assert!(matches!(
            plan.render(),
            Err(PlanError::StagedFdMissing("credential"))
        ));
    }
    // J3-launch end
}
