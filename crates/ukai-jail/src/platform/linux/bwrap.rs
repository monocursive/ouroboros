//! The bubblewrap plan every contained profile (`tool`, `build`, `agent`)
//! renders: argv, mount table, and the placeholder mount points an absent
//! protected literal needs.
//!
//! jail-v1 §9.1 and §9.2, north-star §4.3. The plan is data; rendering it is
//! a pure function, so the argv and the mount table the receipt records come
//! from the same structure and cannot disagree.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::clock::Deadline;
use super::exec::run_captured;
use super::fs::{RootSpec, exists_resolved, resolve_runtime_root};
use super::sys::{PathError, cstring_from_os, errno_name, last_errno};
use crate::state::anchored::{Dir, Kind, Name, fstat};

/// Where the jail's own binary is bound inside the sandbox.
pub const JAIL_INSIDE_PATH: &str = "/run/ukai/jail";
/// Where the scratch directory appears inside the sandbox.
pub const SCRATCH_INSIDE_PATH: &str = "/tmp";
/// Where vendor state appears inside the sandbox. jail-v1 §9.1 fixes no
/// location; this is beside [`JAIL_INSIDE_PATH`], under the sandbox's own
/// read-only `/run/ukai`, so its parent (the attempt directory) is never
/// visible and no operator grant can shadow it.
pub const VENDOR_STATE_INSIDE_PATH: &str = "/run/ukai/state";
/// Where the attempt's proxy directory appears inside the sandbox, read-only
/// (jail-v1 §10: "Expose only its dedicated directory at `/run/ukai/proxy`,
/// read-only to the child").
pub const PROXY_INSIDE_PATH: &str = "/run/ukai/proxy";

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
/// instead of the command line: ARG_MAX is normally 2 MiB, and this keeps a
/// wide margin below it.
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

impl BwrapVersion {
    /// Whether this backend is new enough for the argv this product
    /// renders: `--bind-fd` and `--ro-bind-fd` arrived in 0.10.0.
    #[must_use]
    pub fn at_least(&self, minimum: (u32, u32, u32)) -> bool {
        (self.major, self.minor, self.patch) >= minimum
    }
}

/// The oldest bubblewrap the rendered argv works with: 0.10.0 introduced
/// `--bind-fd` and `--ro-bind-fd`, which every contained run uses.
pub const MINIMUM_VERSION: (u32, u32, u32) = (0, 10, 0);

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

/// Run `bwrap --version` with an empty environment, no stdin and `deadline`.
///
/// The question is asked inside the preparation budget and by `doctor`, so a
/// backend that hangs, reads its standard input or is steered by the
/// operator's environment must not stall or colour the answer: past the
/// deadline it is killed and the version is unknown.
///
/// # Errors
///
/// A failure to run the binary, a run the deadline ended, an unsuccessful
/// exit, or output that does not parse.
pub fn bwrap_version(bwrap: &Path, deadline: Deadline) -> io::Result<BwrapVersion> {
    let mut command = Command::new(bwrap);
    command.arg("--version").env_clear().stdin(Stdio::null());
    let out = run_captured(&mut command, deadline)?;
    if out.timed_out {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{} --version did not answer in time", bwrap.display()),
        ));
    }
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{} --version exited {:?}",
            bwrap.display(),
            out.status.code()
        )));
    }
    parse_version(&out.stdout)
        .ok_or_else(|| io::Error::other(format!("unparsed version {:?}", out.stdout)))
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

/// The parent of `path`, opened without following a symlink at its final
/// component, and `path`'s last component.
fn anchor(path: &Path) -> io::Result<(Dir, Name)> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    };
    let name =
        Name::new(name.as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    Ok((Dir::open_trusted(parent)?, name))
}

fn errno_of(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(libc::EIO)
}

impl Placeholder {
    /// Create the empty source directory and the destination mount point, and
    /// register the destination's identity.
    ///
    /// The destination is created, opened and later removed relative to one
    /// handle on its parent, never by its full path, so a symlinked parent
    /// cannot redirect any of the three.
    ///
    /// # Errors
    ///
    /// [`PlaceholderError::DestinationExists`] when the destination is already
    /// there — the caller must then treat it as a pre-existing protected
    /// segment — or an I/O errno.
    pub fn create(source: &Path, destination: &Path) -> Result<Self, PlaceholderError> {
        let source_c = cstring_from_os(source.as_os_str()).map_err(PlaceholderError::Path)?;
        cstring_from_os(destination.as_os_str()).map_err(PlaceholderError::Path)?;
        let at_destination = |error: io::Error| PlaceholderError::Io {
            path: destination.to_owned(),
            errno: errno_of(&error),
        };

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
        let (parent, name) = anchor(destination).map_err(at_destination)?;
        let created = parent.mkdir_at(&name, 0o700).map_err(|error| {
            if error.raw_os_error() == Some(libc::EEXIST) {
                PlaceholderError::DestinationExists(destination.to_owned())
            } else {
                at_destination(error)
            }
        })?;

        // The handle is taken immediately, so the identity registered below is
        // one that cannot be handed to another object while this lives. It is
        // checked against the directory `mkdir_at` opened, so it is the
        // directory just created.
        let handle = parent.open_path_at(&name).map_err(at_destination)?;
        let stat = fstat(handle.as_fd()).map_err(at_destination)?;
        if stat.identity() != created.stat().map_err(at_destination)?.identity() {
            return Err(PlaceholderError::Io {
                path: destination.to_owned(),
                errno: libc::ESTALE,
            });
        }
        Ok(Self {
            mount: PlaceholderMount {
                source: source.to_owned(),
                destination: destination.to_owned(),
            },
            dev: stat.dev,
            ino: stat.ino,
            uid: stat.uid,
            mode: stat.mode,
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
        let (parent, name) = match anchor(&path) {
            Ok(anchored) => anchored,
            Err(error) => return PlaceholderOutcome::KeptError(path, errno_of(&error)),
        };

        // What this code is holding.
        let held = match fstat(self.handle.as_fd()) {
            Ok(held) => held,
            Err(error) => return PlaceholderOutcome::KeptError(path, errno_of(&error)),
        };

        // What the name refers to now.
        let now = match parent.stat_at(&name) {
            Ok(now) => now,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                return PlaceholderOutcome::AlreadyGone(path);
            }
            Err(error) => return PlaceholderOutcome::KeptError(path, errno_of(&error)),
        };
        if now.kind != Kind::Directory {
            return PlaceholderOutcome::KeptChanged(path, "no longer a directory".to_owned());
        }
        if now.identity() != held.identity() {
            return PlaceholderOutcome::KeptChanged(
                path,
                format!(
                    "identity changed from {}:{} to {}:{}",
                    held.dev, held.ino, now.dev, now.ino
                ),
            );
        }
        if now.uid != self.uid {
            return PlaceholderOutcome::KeptChanged(path, "owner changed".to_owned());
        }
        if now.mode != self.mode {
            return PlaceholderOutcome::KeptChanged(path, "permissions changed".to_owned());
        }

        // Emptiness, through a fresh descriptor for the same entry — and that
        // descriptor is checked against the handle too, so the window between
        // the stat above and this open cannot be used to swap the object.
        let entry = match parent.open_dir_at(&name, None) {
            Ok(entry) => entry,
            Err(error) => {
                return match error.raw_os_error() {
                    Some(libc::ENOENT) => PlaceholderOutcome::AlreadyGone(path),
                    Some(libc::ENOTDIR | libc::ELOOP) => {
                        PlaceholderOutcome::KeptChanged(path, "no longer a directory".to_owned())
                    }
                    _ => PlaceholderOutcome::KeptError(path, errno_of(&error)),
                };
            }
        };
        match entry.stat() {
            Ok(opened) if opened.identity() == held.identity() => {}
            Ok(_) => {
                return PlaceholderOutcome::KeptChanged(
                    path,
                    "the entry was replaced while it was being checked".to_owned(),
                );
            }
            Err(error) => return PlaceholderOutcome::KeptError(path, errno_of(&error)),
        }
        match entry.names(1) {
            Ok(listing) if listing.names.is_empty() => {}
            Ok(_) => return PlaceholderOutcome::KeptNotEmpty(path),
            Err(error) => return PlaceholderOutcome::KeptError(path, errno_of(&error)),
        }
        drop(entry);

        if let Err(error) = parent.rmdir_at(&name) {
            return PlaceholderOutcome::KeptError(path, errno_of(&error));
        }
        let _ = std::fs::remove_dir(&self.mount.source);
        PlaceholderOutcome::Removed(path)
    }
}

/// The placeholders one preparation created, until a boundary owns them.
///
/// A placeholder is a directory created in the operator's workspace. The
/// boundary removes its placeholders itself, once the tree is known dead
/// (§9.1); before a boundary exists every refusal of the preparation would
/// otherwise leave an empty `.git` or `.ukai` behind. So until
/// [`PlaceholderSet::hand_over`] passes them on, dropping the set removes
/// each placeholder that is unchanged and empty, and keeps any other.
#[derive(Debug, Default)]
pub struct PlaceholderSet {
    placeholders: Vec<Placeholder>,
}

impl PlaceholderSet {
    /// Holds one more placeholder.
    pub fn push(&mut self, placeholder: Placeholder) {
        self.placeholders.push(placeholder);
    }

    /// How many placeholders are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.placeholders.len()
    }

    /// Whether none are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.placeholders.is_empty()
    }

    /// Passes the placeholders to an owner that removes them itself; this
    /// set then removes nothing.
    #[must_use]
    pub fn hand_over(mut self) -> Vec<Placeholder> {
        std::mem::take(&mut self.placeholders)
    }
}

impl Drop for PlaceholderSet {
    fn drop(&mut self) {
        for placeholder in &self.placeholders {
            let _ = placeholder.remove_if_unchanged();
        }
    }
}

/// The creation time of an open object, where the filesystem records one.
///
/// `None` on a filesystem that keeps no birth time, which is why this is
/// recorded as evidence beside the handle rather than relied on: a check that
/// silently passes wherever the fact is absent is not a check.
fn birth_time(handle: &OwnedFd) -> Option<(i64, u32)> {
    // SAFETY: `statx` is a plain C struct of integers, for which all-zero is
    // a valid value; the call below overwrites it.
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

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// What one mount-table row does. [`MountKind::as_str`] is the row's
/// spelling; [`MountRow`]'s rendering is decided by this alone, so every
/// kind is handled once, by an exhaustive match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MountKind {
    /// A host path bound read-only over the destination.
    RoBind,
    /// A host path bound writable.
    Bind,
    /// A recreated merged-`/usr` symlink; the source is its target.
    Symlink,
    /// The sandbox's own `/proc`.
    Proc,
    /// The sandbox's own minimal `/dev`.
    Dev,
    /// An allowlisted host device node, bound on its own.
    DevBind,
    /// The ungranted workspace: an empty tmpfs, sealed read-only once every
    /// grant beneath it is mounted.
    Cwd,
    /// An empty directory bound read-only over an absent protected literal.
    Placeholder,
    /// Vendor state, writable, bound by descriptor only.
    VendorState,
    /// A `bind_ro` credential view, bound by descriptor only; its source is
    /// private operational state and never appears in the row.
    Credential,
    /// The attempt's proxy directory, read-only, bound by descriptor only.
    Proxy,
    /// A denied directory: an empty tmpfs, read-only from the start.
    TmpfsMask,
    /// A denied file: an empty, mode-000 file read from a data descriptor.
    FileMask,
}

/// What preparation gives a row before it can render.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountPreparation {
    /// Pin the source and hand bubblewrap its descriptor, so a path swap
    /// between validation and mount cannot redirect the bind.
    PinSource,
    /// Hand bubblewrap an empty data descriptor to make the file from.
    EmptyData,
    /// Nothing: the row has no host source, or its descriptor is staged.
    Nothing,
}

impl MountKind {
    /// The row's spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RoBind => "ro-bind",
            Self::Bind => "bind",
            Self::Symlink => "symlink",
            Self::Proc => "proc",
            Self::Dev => "dev",
            Self::DevBind => "dev-bind",
            Self::Cwd => "cwd",
            Self::Placeholder => "placeholder",
            Self::VendorState => "vendor-state",
            Self::Credential => "credential",
            Self::Proxy => "proxy",
            Self::TmpfsMask => "tmpfs-mask",
            Self::FileMask => "file-mask",
        }
    }

    /// What preparation gives a row of this kind.
    #[must_use]
    pub fn preparation(self) -> MountPreparation {
        match self {
            Self::RoBind | Self::Bind | Self::Placeholder => MountPreparation::PinSource,
            Self::FileMask => MountPreparation::EmptyData,
            Self::Symlink
            | Self::Proc
            | Self::Dev
            | Self::DevBind
            | Self::Cwd
            | Self::VendorState
            | Self::Credential
            | Self::Proxy
            | Self::TmpfsMask => MountPreparation::Nothing,
        }
    }
}

impl fmt::Display for MountKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row of the mount table, in the order the mounts are applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountRow {
    /// What the row does.
    pub kind: MountKind,
    /// The host source, or the symlink target; nothing for a mount with no
    /// host source (`proc`, `dev`, `cwd`, the masks) and for a credential
    /// view, whose source is never recorded.
    pub source: Option<OsString>,
    /// The path inside the sandbox.
    pub destination: OsString,
    /// The descriptor number, valid in the bubblewrap process, the mount is
    /// made from: a staged object's, a pinned source's, or a file mask's
    /// empty data. `None` binds `source` by path, or has nothing to bind.
    pub fd: Option<RawFd>,
}

impl MountRow {
    fn new(kind: MountKind, source: Option<&OsStr>, destination: &OsStr) -> Self {
        Self {
            kind,
            source: source.map(OsStr::to_owned),
            destination: destination.to_owned(),
            fd: None,
        }
    }

    /// The row with its descriptor.
    fn with_fd(self, fd: Option<RawFd>) -> Self {
        Self { fd, ..self }
    }

    /// Whether `other` is the same mount, whatever descriptors either has.
    fn same_mount(&self, other: &Self) -> bool {
        (self.kind, &self.source, &self.destination)
            == (other.kind, &other.source, &other.destination)
    }

    /// The bubblewrap options this row renders to.
    ///
    /// # Errors
    /// [`PlanError::StagedFdMissing`] for a row that is made only from a
    /// descriptor and has none, or [`PlanError::IncompleteRow`] for a bind
    /// with neither a descriptor nor a source.
    fn emit(&self, out: &mut Vec<OsString>) -> Result<(), PlanError> {
        let destination = self.destination.clone();
        let fd = |what: &'static str| -> Result<OsString, PlanError> {
            self.fd
                .map(|fd| OsString::from(fd.to_string()))
                .ok_or(PlanError::StagedFdMissing(what))
        };
        let source = || {
            self.source
                .clone()
                .ok_or(PlanError::IncompleteRow(self.kind.as_str()))
        };
        let bind = |by_path: &str, by_fd: &str| -> Result<[OsString; 3], PlanError> {
            Ok(match self.fd {
                Some(fd) => [by_fd.into(), fd.to_string().into(), destination.clone()],
                None => [by_path.into(), source()?, destination.clone()],
            })
        };
        match self.kind {
            MountKind::RoBind | MountKind::Placeholder => {
                out.extend(bind("--ro-bind", "--ro-bind-fd")?);
            }
            MountKind::Bind => out.extend(bind("--bind", "--bind-fd")?),
            MountKind::Symlink => out.extend(["--symlink".into(), source()?, destination]),
            MountKind::Proc => out.extend(["--proc".into(), destination]),
            MountKind::Dev => out.extend(["--dev".into(), destination]),
            MountKind::DevBind => out.extend(["--dev-bind".into(), source()?, destination]),
            MountKind::Cwd => out.extend(["--tmpfs".into(), destination]),
            MountKind::VendorState => {
                out.extend(["--bind-fd".into(), fd("vendor-state")?, destination]);
            }
            MountKind::Credential => {
                out.extend(["--ro-bind-fd".into(), fd("credential")?, destination]);
            }
            MountKind::Proxy => {
                out.extend(["--ro-bind-fd".into(), fd("proxy directory")?, destination]);
            }
            // A denied path is absent or masked, never writable scratch
            // outside every quota view: the mask is sealed read-only the
            // moment it exists.
            MountKind::TmpfsMask => out.extend([
                "--tmpfs".into(),
                destination.clone(),
                "--remount-ro".into(),
                destination,
            ]),
            MountKind::FileMask => out.extend([
                "--perms".into(),
                "000".into(),
                "--ro-bind-data".into(),
                fd("file denial")?,
                destination,
            ]),
        }
        Ok(())
    }
}

/// A denial overlays the destination after every grant. Files need a private
/// empty, mode-000 regular file; a directory tmpfs cannot cover a file inode.
#[derive(Clone, Debug)]
pub enum Mask {
    /// An empty, read-only directory.
    Directory(PathBuf),
    /// An unreadable, read-only regular file made from an empty data descriptor.
    File(PathBuf),
}

impl Mask {
    /// Destination in the sandbox, independent of the mask's object type.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Directory(path) | Self::File(path) => path,
        }
    }
}

impl From<&str> for Mask {
    fn from(path: &str) -> Self {
        Self::Directory(path.into())
    }
}

/// How the workspace appears inside the sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceAccess {
    /// An empty working directory, sealed read-only: no undeclared input is
    /// exposed.
    Hidden,
    /// Bound read-only; a writable grant inside it is layered over it.
    ReadOnly,
    /// Bound writable.
    Writable,
}

/// A directory the supervisor staged, bound by the descriptor it holds and
/// never by its path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staged {
    /// The host path, for the mount table and diagnostics only.
    pub host: PathBuf,
    /// Descriptor number, valid in the bubblewrap process, of the staged
    /// directory.
    pub fd: RawFd,
}

/// Everything needed to build a bubblewrap invocation.
///
/// The fields are the crate's; the platform fills them. Other users build a
/// plan with [`BwrapPlan::tool`] and the setters below.
#[derive(Clone, Debug)]
pub struct BwrapPlan {
    /// Path to the `bwrap` binary.
    pub(crate) bwrap: PathBuf,
    /// System roots, already classified into binds and merged-`/usr` symlinks.
    pub(crate) roots: Vec<RootSpec>,
    /// `/etc` grants that exist on this host.
    pub(crate) etc_paths: Vec<PathBuf>,
    /// The workspace, mounted at the same path inside.
    pub(crate) workspace: PathBuf,
    /// J12: the child's working directory inside when it is not the
    /// workspace: the directory beneath it the operator stood in
    /// (`roots.cwd`).
    pub(crate) cwd: Option<PathBuf>,
    /// How the workspace appears.
    pub(crate) workspace_access: WorkspaceAccess,
    /// The scratch directory, mounted at `/tmp` inside.
    pub(crate) scratch: PathBuf,
    /// Seal /dev, including /dev/shm, against filesystem allocation.
    pub(crate) bounded_storage: bool,
    /// Environment to set after `--clearenv`.
    pub(crate) env: Vec<(OsString, OsString)>,
    /// Extra read-only binds with a destination of their own: operator
    /// `--ro` grants (§6.1), the protected segments the preparation pinned
    /// (each at its destination inside the sandbox, which for the scratch is
    /// not its host path), the vault CA, and the doctor probes' binds. A row
    /// whose pin was handed to the spawn map renders as `--ro-bind-fd`.
    pub(crate) extra_ro_binds: Vec<(PathBuf, PathBuf)>,
    /// Extra writable binds from operator `--rw` grants, applied after the
    /// workspace bind so a grant inside it stays writable (§6.1).
    pub(crate) extra_rw_binds: Vec<(PathBuf, PathBuf)>,
    /// Operator `--rw` grants of allowlisted device nodes: NVIDIA nodes,
    /// bound individually with `--dev-bind` so a contained profile can use a
    /// GPU without ever seeing devtmpfs.
    pub(crate) extra_dev_binds: Vec<(PathBuf, PathBuf)>,
    /// Denied paths, masked with a read-only directory tmpfs or an unreadable
    /// read-only file after every other mount (north-star §4.3).
    pub(crate) masked: Vec<Mask>,
    /// Placeholders for absent root-level literals.
    pub(crate) placeholders: Vec<PlaceholderMount>,
    /// The jail binary to bind at [`JAIL_INSIDE_PATH`].
    pub(crate) jail_exe: PathBuf,
    /// Descriptor carrying the seccomp program.
    pub(crate) seccomp_fd: Option<RawFd>,
    /// Descriptor bubblewrap writes its own JSON status to.
    pub(crate) json_status_fd: Option<RawFd>,
    /// Descriptor to read the options from, when they are too many for the
    /// command line ([`ARGS_FD_THRESHOLD`]).
    pub(crate) args_fd: Option<RawFd>,
    /// The command inside the sandbox, normally
    /// `/run/ukai/jail __launch ... -- PROGRAM ARG...`.
    pub(crate) inner: Vec<OsString>,
    /// Vendor state, bound writable at [`VENDOR_STATE_INSIDE_PATH`] by
    /// descriptor only (§9.1, §12).
    pub(crate) vendor_state: Option<Staged>,
    /// `bind_ro` credential views: each exact source object's descriptor and
    /// its destination under [`VENDOR_STATE_INSIDE_PATH`] (`--ro-bind-fd`).
    pub(crate) credential_binds: Vec<CredentialBind>,
    /// The attempt's proxy directory, bound read-only at
    /// [`PROXY_INSIDE_PATH`] by descriptor only (§10).
    pub(crate) proxy_dir: Option<Staged>,
    /// When set, the file bound at `/etc/resolv.conf` is this sanitized
    /// per-attempt copy instead of the host's: the host file can carry the
    /// operator's search domains, which are host facts the child has no
    /// grant for. The child's resolver is unreachable in its network
    /// namespace either way; `etc_paths` still lists `/etc/resolv.conf`
    /// so operator-grant overlap checks keep their meaning.
    pub(crate) resolv_source: Option<PathBuf>,
    /// The table preparation gave descriptors to ([`Self::set_mount_descriptors`]);
    /// rendering refuses if the plan's table has changed since.
    prepared: Option<Vec<MountRow>>,
}

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
    /// A mount made only from a descriptor has none; staged objects and
    /// file denials are never bound by path.
    StagedFdMissing(&'static str),
    /// A bind row has neither a descriptor nor a source.
    IncompleteRow(&'static str),
    /// The mount table is not the one preparation gave descriptors to.
    MountsChanged,
    /// An argument contains NUL, which would split it into several options
    /// in the NUL-separated `--args` payload.
    ArgumentNul,
    /// A `deny_read` mask that would shadow the boundary's own plumbing
    /// (`/run`, `/run/ukai` or beneath it: the jail binary, the proxy
    /// directory and staged vendor state).
    MaskedBoundaryPlumbing(PathBuf),
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
            Self::StagedFdMissing(what) => {
                write!(
                    f,
                    "the {what} mount has no descriptor; it is never bound by path"
                )
            }
            Self::IncompleteRow(kind) => {
                write!(f, "a {kind} mount has neither a descriptor nor a source")
            }
            Self::MountsChanged => write!(
                f,
                "the mount table changed after preparation gave its rows their descriptors"
            ),
            Self::ArgumentNul => write!(
                f,
                "an argument contains NUL, which would split it into bubblewrap options"
            ),
            Self::MaskedBoundaryPlumbing(path) => write!(
                f,
                "a deny_read mask at {} would shadow the boundary's own plumbing \
                 (/run/ukai: the jail binary, the proxy directory, staged state)",
                path.display()
            ),
        }
    }
}

/// Whether a `deny_read` mask destination would cover the boundary's own
/// plumbing. The jail binary ([`JAIL_INSIDE_PATH`]), the proxy directory
/// ([`PROXY_INSIDE_PATH`]) and staged vendor state
/// ([`VENDOR_STATE_INSIDE_PATH`]) all live under `/run/ukai` in the sandbox
/// view, so a tmpfs at `/`, `/run` or `/run/ukai` shadows them all and one
/// beneath `/run/ukai` shadows part of it — the launcher's own binary or the
/// socket its bridge connects through. Such a mask never narrows the child's
/// authority; it attacks the next run's plumbing, so both the policy layer
/// and this renderer refuse it.
///
/// The comparison is by path component, so `/run//ukai`, `/run/./ukai` and
/// `///run` are the paths they name. A `..` component cannot be placed
/// without resolving it, so a mask holding one is refused as if it reached
/// the plumbing.
fn shadows_plumbing(path: &Path) -> bool {
    use std::path::Component;
    let plumbing = [
        Component::RootDir,
        Component::Normal(OsStr::new("run")),
        Component::Normal(OsStr::new("ukai")),
    ];
    let components: Vec<Component<'_>> = path.components().collect();
    if components.is_empty() {
        return false;
    }
    if components.contains(&Component::ParentDir) {
        return true;
    }
    // One is a prefix of the other: the mask covers the plumbing, or lies
    // beneath it.
    let shared = components.len().min(plumbing.len());
    components[..shared] == plumbing[..shared]
}

impl std::error::Error for PlanError {}

/// A rendered invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// The argv to execute, including `bwrap` itself.
    pub argv: Vec<OsString>,
    /// When present, the NUL-separated options to write to the plan's
    /// `--args` descriptor; `argv` is then `bwrap --args FD -- COMMAND...`.
    pub args_payload: Option<Vec<u8>>,
}

/// The namespace and lifetime options every contained plan starts with.
const NAMESPACE_OPTIONS: [&str; 9] = [
    "--unshare-user",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    // §9.1: no host namespace handle reaches the child. Without this the
    // child reads the supervisor's own cgroup path out of /proc/self/cgroup,
    // which names the operator's session.
    "--unshare-cgroup",
    "--die-with-parent",
    "--new-session",
    "--clearenv",
];

impl BwrapPlan {
    /// A `tool` plan with this host's runtime roots and `/etc` grants filled
    /// in, a writable workspace, and a default `PATH` and `TMPDIR`.
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
            cwd: None,
            workspace_access: WorkspaceAccess::Writable,
            scratch: scratch.to_owned(),
            bounded_storage: false,
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
            extra_ro_binds: Vec::new(),
            extra_rw_binds: Vec::new(),
            extra_dev_binds: Vec::new(),
            masked: Vec::new(),
            placeholders: Vec::new(),
            jail_exe: jail_exe.to_owned(),
            seccomp_fd: None,
            json_status_fd: None,
            args_fd: None,
            inner: Vec::new(),
            vendor_state: None,
            credential_binds: Vec::new(),
            proxy_dir: None,
            resolv_source: None,
            prepared: None,
        }
    }

    /// Run this `bwrap` binary.
    pub fn set_backend(&mut self, bwrap: &Path) {
        bwrap.clone_into(&mut self.bwrap);
    }

    /// The command to run inside the sandbox.
    pub fn set_command(&mut self, inner: Vec<OsString>) {
        self.inner = inner;
    }

    /// Set one environment variable for the command, replacing any earlier
    /// value.
    pub fn set_env(&mut self, name: impl Into<OsString>, value: impl Into<OsString>) {
        let name = name.into();
        self.env.retain(|(existing, _)| *existing != name);
        self.env.push((name, value.into()));
    }

    /// Load the seccomp program from this descriptor (`--seccomp`).
    pub fn set_seccomp_fd(&mut self, fd: RawFd) {
        self.seccomp_fd = Some(fd);
    }

    /// Have bubblewrap write its JSON status here (`--json-status-fd`).
    pub fn set_json_status_fd(&mut self, fd: RawFd) {
        self.json_status_fd = Some(fd);
    }

    /// Where the options go when they are too many for the command line.
    pub fn set_args_fd(&mut self, fd: RawFd) {
        self.args_fd = Some(fd);
    }

    /// Bind `source` read-only at `destination`.
    pub fn bind_read_only(&mut self, source: PathBuf, destination: PathBuf) {
        self.extra_ro_binds.push((source, destination));
    }

    /// Mount a placeholder over an absent protected literal.
    pub fn add_placeholder(&mut self, placeholder: PlaceholderMount) {
        self.placeholders.push(placeholder);
    }

    /// Bind staged vendor state, by its descriptor.
    pub fn stage_vendor_state(&mut self, vendor_state: Staged) {
        self.vendor_state = Some(vendor_state);
    }

    /// Bind one credential view, by its descriptor.
    pub fn add_credential_view(&mut self, view: CredentialBind) {
        self.credential_binds.push(view);
    }

    /// The mount table, in the order the mounts are applied, with the
    /// descriptors the plan itself holds (staged objects, protected pins).
    #[must_use]
    pub fn mount_table(&self) -> Vec<MountRow> {
        let mut rows = self.runtime_rows();
        rows.extend(self.base_rows());
        rows.extend(self.grant_rows());
        // After every operator grant, so no `--ro`/`--rw` of an ancestor of
        // `/run/ukai` can shadow them; before the masks, like the jail binary.
        rows.extend(self.staged_rows());
        rows.push(MountRow::new(
            MountKind::RoBind,
            Some(self.jail_exe.as_os_str()),
            OsStr::new(JAIL_INSIDE_PATH),
        ));
        rows.extend(self.mask_rows());
        rows
    }

    /// The system roots, the `/etc` grants, `/proc` and `/dev`.
    fn runtime_rows(&self) -> Vec<MountRow> {
        let mut rows: Vec<MountRow> = self
            .roots
            .iter()
            .map(|root| match root {
                RootSpec::RoBind(path) => {
                    MountRow::new(MountKind::RoBind, Some(path.as_os_str()), path.as_os_str())
                }
                RootSpec::Symlink { path, target } => MountRow::new(
                    MountKind::Symlink,
                    Some(target.as_os_str()),
                    path.as_os_str(),
                ),
            })
            .collect();
        for etc in &self.etc_paths {
            // `/etc/resolv.conf` binds the sanitized per-attempt copy when
            // one was staged.
            let source = match &self.resolv_source {
                Some(sanitized) if etc == Path::new("/etc/resolv.conf") => sanitized,
                _ => etc,
            };
            rows.push(MountRow::new(
                MountKind::RoBind,
                Some(source.as_os_str()),
                etc.as_os_str(),
            ));
        }
        rows.push(MountRow::new(MountKind::Proc, None, OsStr::new("/proc")));
        rows.push(MountRow::new(MountKind::Dev, None, OsStr::new("/dev")));
        rows
    }

    /// The base roots, ancestors before descendants. The workspace is one of
    /// them in whichever mode the plan grants it: a read-only workspace sits
    /// under any writable grant inside it rather than covering it, and a
    /// hidden one is an empty tmpfs mounted after a scratch at /tmp that
    /// would otherwise hide it, then sealed read-only by the argv once every
    /// grant beneath it is in place.
    fn base_rows(&self) -> Vec<MountRow> {
        let mut rows: Vec<MountRow> = self
            .extra_rw_binds
            .iter()
            .map(|(source, destination)| {
                MountRow::new(
                    MountKind::Bind,
                    Some(source.as_os_str()),
                    destination.as_os_str(),
                )
            })
            .collect();
        rows.push(MountRow::new(
            MountKind::Bind,
            Some(self.scratch.as_os_str()),
            OsStr::new(SCRATCH_INSIDE_PATH),
        ));
        let workspace = self.workspace.as_os_str();
        rows.push(match self.workspace_access {
            WorkspaceAccess::Writable => MountRow::new(MountKind::Bind, Some(workspace), workspace),
            WorkspaceAccess::ReadOnly => {
                MountRow::new(MountKind::RoBind, Some(workspace), workspace)
            }
            WorkspaceAccess::Hidden => MountRow::new(MountKind::Cwd, None, workspace),
        });
        rows.sort_by_key(|row| Path::new(&row.destination).components().count());
        rows
    }

    /// Device nodes, read-only binds (ancestors first) and placeholders.
    fn grant_rows(&self) -> Vec<MountRow> {
        let mut rows: Vec<MountRow> = self
            .extra_dev_binds
            .iter()
            .map(|(source, destination)| {
                MountRow::new(
                    MountKind::DevBind,
                    Some(source.as_os_str()),
                    destination.as_os_str(),
                )
            })
            .collect();
        let mut readonly: Vec<&(PathBuf, PathBuf)> = self.extra_ro_binds.iter().collect();
        readonly.sort_by_key(|(_, destination)| destination.components().count());
        rows.extend(readonly.into_iter().map(|(source, destination)| {
            MountRow::new(
                MountKind::RoBind,
                Some(source.as_os_str()),
                destination.as_os_str(),
            )
        }));
        rows.extend(self.placeholders.iter().map(|placeholder| {
            MountRow::new(
                MountKind::Placeholder,
                Some(placeholder.source.as_os_str()),
                placeholder.destination.as_os_str(),
            )
        }));
        rows
    }

    /// Vendor state, the credential views inside it, then the proxy
    /// directory: each bound by the descriptor staging holds.
    fn staged_rows(&self) -> Vec<MountRow> {
        let mut rows = Vec::new();
        if let Some(vendor) = &self.vendor_state {
            rows.push(
                MountRow::new(
                    MountKind::VendorState,
                    Some(vendor.host.as_os_str()),
                    OsStr::new(VENDOR_STATE_INSIDE_PATH),
                )
                .with_fd(Some(vendor.fd)),
            );
        }
        let mut views: Vec<&CredentialBind> = self.credential_binds.iter().collect();
        views.sort_by_key(|view| view.destination.components().count());
        rows.extend(views.into_iter().map(|view| {
            MountRow::new(MountKind::Credential, None, view.destination.as_os_str())
                .with_fd(view.fd)
        }));
        if let Some(proxy) = &self.proxy_dir {
            rows.push(
                MountRow::new(
                    MountKind::Proxy,
                    Some(proxy.host.as_os_str()),
                    OsStr::new(PROXY_INSIDE_PATH),
                )
                .with_fd(Some(proxy.fd)),
            );
        }
        rows
    }

    /// The denials, ancestors first. An ancestor denial already hides
    /// everything beneath it, so a nested mask inside it is not rendered.
    fn mask_rows(&self) -> Vec<MountRow> {
        let mut masks: Vec<&Mask> = self.masked.iter().collect();
        masks.sort_by_key(|mask| mask.path().components().count());
        let mut rows: Vec<MountRow> = Vec::new();
        for mask in masks {
            let path = mask.path();
            if rows
                .iter()
                .any(|ancestor| path.starts_with(&ancestor.destination))
            {
                continue;
            }
            let kind = match mask {
                Mask::File(_) => MountKind::FileMask,
                Mask::Directory(_) => MountKind::TmpfsMask,
            };
            rows.push(MountRow::new(kind, None, path.as_os_str()));
        }
        rows
    }

    /// Record the descriptors preparation gave the rows of
    /// [`Self::mount_table`]: `rows` is that table with each [`MountRow::fd`]
    /// preparation set. The descriptors travel with their rows, and
    /// rendering refuses a plan whose table has changed since.
    ///
    /// # Errors
    /// [`PlanError::MountsChanged`] when `rows` is not this plan's table.
    pub(crate) fn set_mount_descriptors(&mut self, rows: Vec<MountRow>) -> Result<(), PlanError> {
        let table = self.mount_table();
        if rows.len() != table.len() || !rows.iter().zip(&table).all(|(a, b)| a.same_mount(b)) {
            return Err(PlanError::MountsChanged);
        }
        self.prepared = Some(rows);
        Ok(())
    }

    /// The table to render: [`Self::mount_table`], each row with the
    /// descriptor preparation gave it, or its own.
    ///
    /// # Errors
    /// [`PlanError::MountsChanged`] when the table is not the one
    /// preparation gave descriptors to.
    pub(crate) fn mount_rows(&self) -> Result<Vec<MountRow>, PlanError> {
        let table = self.mount_table();
        let Some(prepared) = &self.prepared else {
            return Ok(table);
        };
        if prepared.len() != table.len() {
            return Err(PlanError::MountsChanged);
        }
        table
            .into_iter()
            .zip(prepared)
            .map(|(row, prepared)| {
                if row.same_mount(prepared) {
                    let fd = prepared.fd.or(row.fd);
                    Ok(row.with_fd(fd))
                } else {
                    Err(PlanError::MountsChanged)
                }
            })
            .collect()
    }

    /// The fewest rows the boundary's `mountinfo` holds under this plan: the
    /// tmpfs bubblewrap makes the root, and one mount per row of
    /// [`BwrapPlan::mount_table`] that mounts something (a symlink does not).
    /// The true count is higher: `/dev` brings its device nodes and `devpts`
    /// beneath it, and a bind brings the host's mounts beneath its source.
    #[must_use]
    pub fn mount_rows_at_least(&self) -> usize {
        1 + self
            .mount_table()
            .iter()
            .filter(|row| row.kind != MountKind::Symlink)
            .count()
    }

    /// Render the invocation.
    ///
    /// # Errors
    ///
    /// [`PlanError`] for a relative path, an unusable path, a missing command,
    /// a staged mount or file denial with no descriptor, a mask over the
    /// boundary's plumbing, a table changed since preparation, an argument
    /// carrying NUL, or a long list with no `--args` descriptor.
    pub fn render(&self) -> Result<Rendered, PlanError> {
        self.validate()?;
        let mut options: Vec<OsString> = NAMESPACE_OPTIONS.iter().map(OsString::from).collect();
        for (key, value) in &self.env {
            options.extend(["--setenv".into(), key.clone(), value.clone()]);
        }
        for row in self.mount_rows()? {
            row.emit(&mut options)?;
        }
        self.seal(&mut options);
        self.pack(options)
    }

    /// The refusals that depend on the plan alone, before anything renders.
    fn validate(&self) -> Result<(), PlanError> {
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
        if self.credential_binds.iter().any(|view| view.fd.is_none()) {
            return Err(PlanError::StagedFdMissing("credential"));
        }
        // A mask is rendered last, over every other row, so one over the
        // plumbing would unmount the jail's own binary, proxy socket or
        // staged state for the whole attempt.
        if let Some(mask) = self
            .masked
            .iter()
            .find(|mask| shadows_plumbing(mask.path()))
        {
            return Err(PlanError::MaskedBoundaryPlumbing(mask.path().to_owned()));
        }
        Ok(())
    }

    /// The options after the mounts: the seals, the working directory and
    /// the descriptors bubblewrap reads or writes.
    fn seal(&self, options: &mut Vec<OsString>) {
        if self.workspace_access == WorkspaceAccess::Hidden {
            // Every grant inside the empty working directory is mounted by
            // now; seal it before the root.
            options.extend(["--remount-ro".into(), self.workspace.clone().into()]);
        }
        options.extend(["--remount-ro".into(), "/".into()]);
        if self.bounded_storage {
            options.extend(["--remount-ro".into(), "/dev".into()]);
        }
        options.extend([
            "--chdir".into(),
            self.cwd.as_ref().unwrap_or(&self.workspace).clone().into(),
        ]);
        if let Some(fd) = self.seccomp_fd {
            options.extend(["--seccomp".into(), fd.to_string().into()]);
        }
        if let Some(fd) = self.json_status_fd {
            options.extend(["--json-status-fd".into(), fd.to_string().into()]);
        }
    }

    /// The argv: the options on the command line, or in the `--args`
    /// payload once they pass [`ARGS_FD_THRESHOLD`]; the command after `--`
    /// either way.
    fn pack(&self, options: Vec<OsString>) -> Result<Rendered, PlanError> {
        // No argument may carry a NUL. The `--args` payload separates options
        // with NUL, so one embedded in an environment name or value would
        // become further bubblewrap options; the launch grammar refuses NUL,
        // and this refuses it again here.
        let all = || options.iter().chain(self.inner.iter());
        if all().any(|part| part.as_bytes().contains(&0)) {
            return Err(PlanError::ArgumentNul);
        }
        let size: usize = all().map(|part| part.as_bytes().len() + 1).sum();
        let mut argv = vec![self.bwrap.as_os_str().to_owned()];
        let payload = if size > ARGS_FD_THRESHOLD {
            let fd = self.args_fd.ok_or(PlanError::ArgsFdMissing)?;
            // Measured on bubblewrap 0.11.1: `--args FD` supplies options
            // only. A command inside the file leaves bubblewrap with nothing
            // to run and it exits with its usage message. The command stays
            // on the command line, after the `--` separator.
            let mut payload = Vec::with_capacity(size);
            for part in &options {
                payload.extend_from_slice(part.as_bytes());
                payload.push(0);
            }
            argv.extend(["--args".into(), fd.to_string().into()]);
            Some(payload)
        } else {
            argv.extend(options);
            None
        };
        argv.push("--".into());
        argv.extend(self.inner.iter().cloned());
        Ok(Rendered {
            argv,
            args_payload: payload,
        })
    }
}

/// One document bubblewrap writes to `--json-status-fd`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BwrapStatus {
    /// Host pid of the namespace init, when reported.
    pub child_pid: Option<libc::pid_t>,
    /// Exit code of the inner command, when reported.
    pub exit_code: Option<i32>,
    /// The pid namespace bubblewrap created, by inode, when reported.
    pub pid_namespace: Option<u64>,
    /// The mount namespace bubblewrap created, by inode, when reported.
    pub mnt_namespace: Option<u64>,
    /// The network namespace bubblewrap created, by inode, when reported.
    pub net_namespace: Option<u64>,
}

/// Parse bubblewrap's JSON status stream: a sequence of objects, read as
/// far as it is complete.
///
/// The stream is read while bubblewrap still writes it, so its last object
/// may be cut short; that object, and anything after a malformed one, is
/// not read at all rather than read in part. A key that never arrived, or
/// whose value is not an integer in range, is `None` rather than guessed.
#[must_use]
pub fn parse_json_status(raw: &str) -> BwrapStatus {
    let mut status = BwrapStatus::default();
    let documents = serde_json::Deserializer::from_str(raw)
        .into_iter::<serde_json::Map<String, serde_json::Value>>();
    for document in documents {
        let Ok(document) = document else { break };
        let integer = |key: &str| document.get(key).and_then(serde_json::Value::as_i64);
        status.child_pid = status
            .child_pid
            .or_else(|| integer("child-pid").and_then(|v| libc::pid_t::try_from(v).ok()));
        status.exit_code = status
            .exit_code
            .or_else(|| integer("exit-code").and_then(|v| i32::try_from(v).ok()));
        let inode = |key: &str| document.get(key).and_then(serde_json::Value::as_u64);
        status.pid_namespace = status.pid_namespace.or_else(|| inode("pid-namespace"));
        status.mnt_namespace = status.mnt_namespace.or_else(|| inode("mnt-namespace"));
        status.net_namespace = status.net_namespace.or_else(|| inode("net-namespace"));
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    #[test]
    fn versions_parse() {
        let v = parse_version("bubblewrap 0.11.1\n").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (0, 11, 1));
        assert_eq!(v.raw, "bubblewrap 0.11.1");
        assert_eq!(parse_version("bubblewrap 1.0").unwrap().patch, 0);
        assert!(parse_version("").is_none());
        assert!(parse_version("bubblewrap unknown").is_none());
    }

    /// A stand-in backend named `name`: a shell script that does `body`.
    fn fake_backend(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn the_version_question_has_a_deadline_no_environment_and_no_stdin() {
        let dir = tempfile::tempdir().unwrap();
        let deadline = || Deadline::after(std::time::Duration::from_secs(5));
        // A backend that never answers is killed at the deadline, and the
        // version is unknown rather than awaited.
        let hung = fake_backend(dir.path(), "hung", "exec sleep 60");
        let started = std::time::Instant::now();
        let error = bwrap_version(
            &hung,
            Deadline::after(std::time::Duration::from_millis(200)),
        )
        .expect_err("a hung backend has no version");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // The operator's environment does not reach it: `HOME` is set for
        // every test process (the shell sets no default for it).
        let environment = fake_backend(
            dir.path(),
            "environment",
            "[ -z \"${HOME+set}\" ] || exit 3\necho 'bubblewrap 0.11.1'",
        );
        assert_eq!(bwrap_version(&environment, deadline()).unwrap().minor, 11);
        // Its standard input is empty, never the supervisor's.
        let stdin = fake_backend(
            dir.path(),
            "stdin",
            "if read -r line; then exit 4; fi\necho 'bubblewrap 0.11.1'",
        );
        assert_eq!(bwrap_version(&stdin, deadline()).unwrap().patch, 1);
        let failing = fake_backend(dir.path(), "failing", "exit 1");
        assert!(bwrap_version(&failing, deadline()).is_err());
    }

    #[test]
    fn json_status_documents_parse() {
        let raw = r#"{"child-pid": 12574, "mnt-namespace": 4026533229, "net-namespace": 4026533231, "pid-namespace": 4026533230}
{"exit-code": 7}"#;
        assert_eq!(
            parse_json_status(raw),
            BwrapStatus {
                child_pid: Some(12574),
                exit_code: Some(7),
                pid_namespace: Some(4_026_533_230),
                mnt_namespace: Some(4_026_533_229),
                net_namespace: Some(4_026_533_231),
            }
        );
        // A namespace that is not reported, or not as an inode number, is
        // not one: nothing is compared against it.
        assert_eq!(
            parse_json_status(r#"{"child-pid": 1, "pid-namespace": "4026533230"}"#).pid_namespace,
            None
        );
        assert_eq!(parse_json_status("{}"), BwrapStatus::default());
        // A status still being written: the cut-short object is not read in
        // part (a half-written `12` is not an exit code of `1`).
        assert_eq!(
            parse_json_status("{\"child-pid\": 12574}\n{\"exit-code\": 1"),
            BwrapStatus {
                child_pid: Some(12574),
                ..BwrapStatus::default()
            }
        );
        assert_eq!(
            parse_json_status("{\"child-pid\": \"12574\"}"),
            BwrapStatus::default(),
            "a value that is not an integer is not one"
        );
    }

    #[test]
    fn a_placeholder_is_made_beneath_its_parent_never_through_a_symlink() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        match Placeholder::create(&root.join("holder"), &link.join(".git")) {
            Err(PlaceholderError::Io { errno, .. }) => {
                assert!(errno == libc::ELOOP || errno == libc::ENOTDIR, "{errno}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(
            !real.join(".git").exists(),
            "nothing is made through a symlinked parent"
        );
        // Through the real parent it is made, registered and removed.
        let placeholder = Placeholder::create(&root.join("holder"), &real.join(".git")).unwrap();
        let held = std::fs::metadata(real.join(".git")).unwrap();
        assert_eq!(placeholder.identity(), (held.dev(), held.ino()));
        assert_eq!(held.permissions().mode() & 0o7777, 0o700);
        assert_eq!(
            placeholder.remove_if_unchanged(),
            PlaceholderOutcome::Removed(real.join(".git"))
        );
    }

    #[test]
    fn a_dropped_placeholder_set_removes_only_what_is_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut set = PlaceholderSet::default();
        for name in ["kept", "removed"] {
            set.push(
                Placeholder::create(&root.join(format!("holder-{name}")), &root.join(name))
                    .unwrap(),
            );
        }
        assert_eq!(set.len(), 2);
        // Something the run put inside: a placeholder that is not empty is
        // not ours to remove.
        std::fs::write(root.join("kept").join("work"), b"x").unwrap();
        drop(set);
        assert!(
            !root.join("removed").exists(),
            "unchanged and empty: removed"
        );
        assert!(!root.join("holder-removed").exists());
        assert!(root.join("kept").join("work").exists(), "changed: kept");

        // Handed over, the placeholders are their new owner's to remove.
        let mut set = PlaceholderSet::default();
        set.push(Placeholder::create(&root.join("holder-owned"), &root.join("owned")).unwrap());
        let owned = set.hand_over();
        assert!(
            root.join("owned").is_dir(),
            "a handed-over set removes nothing"
        );
        assert_eq!(
            owned[0].remove_if_unchanged(),
            PlaceholderOutcome::Removed(root.join("owned"))
        );
    }

    fn sample_plan() -> BwrapPlan {
        let mut plan = BwrapPlan::tool(
            Path::new("/work/space"),
            Path::new("/scratch/dir"),
            Path::new("/usr/local/bin/ukai-jail"),
        );
        plan.roots = vec![
            RootSpec::RoBind(PathBuf::from("/usr")),
            RootSpec::Symlink {
                path: PathBuf::from("/bin"),
                target: PathBuf::from("usr/bin"),
            },
        ];
        plan.etc_paths = vec![PathBuf::from("/etc/passwd")];
        plan.bind_read_only(
            PathBuf::from("/work/space/.git"),
            PathBuf::from("/work/space/.git"),
        );
        plan.seccomp_fd = Some(10);
        plan.json_status_fd = Some(11);
        plan.inner = super::super::launch::LaunchArgs {
            release_fd: 12,
            error_fd: 13,
            narrow: true,
            read_open_fast_path: false,
            trace_data_fd: None,
            mediate: None,
            bridge: None,
            sigmask: None,
            nofile_soft: None,
            pins: Vec::new(),
            argv: vec![OsString::from("/bin/true")],
        }
        .command_line(OsStr::new(JAIL_INSIDE_PATH));
        plan
    }

    /// An allowlisted device grant renders `--dev-bind`, binding the single
    /// node instead of any devtmpfs surface.
    #[test]
    fn a_device_grant_renders_dev_bind() {
        let mut plan = sample_plan();
        plan.extra_dev_binds
            .push((PathBuf::from("/dev/nvidia0"), PathBuf::from("/dev/nvidia0")));
        let text = argv_strings(&plan);
        let at = text
            .iter()
            .position(|arg| arg == "--dev-bind")
            .expect("a --dev-bind row");
        assert_eq!(
            (text[at + 1].as_str(), text[at + 2].as_str()),
            ("/dev/nvidia0", "/dev/nvidia0")
        );
    }

    #[test]
    fn the_argv_has_the_profile_the_north_star_describes() {
        let plan = sample_plan();
        let text = argv_strings(&plan);
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
        assert!(joined.contains("--ro-bind /usr/local/bin/ukai-jail /run/ukai/jail"));
        assert!(joined.contains("--chdir /work/space"));
        assert!(joined.contains("--seccomp 10"));
        assert!(joined.contains("--json-status-fd 11"));
        assert!(joined.contains("--proc /proc --dev /dev"));
        assert!(joined.ends_with(
            "-- /run/ukai/jail __launch --release-fd 12 --error-fd 13 --narrow -- /bin/true"
        ));
        assert!(plan.render().unwrap().args_payload.is_none());
    }

    #[test]
    fn the_scratch_becomes_tmpdir() {
        assert!(argv_text(&sample_plan()).contains("--setenv TMPDIR /tmp "));
    }

    /// A mask renders last over every other row, so one over the boundary's
    /// own plumbing must refuse the plan outright.
    #[test]
    fn a_mask_over_the_boundary_plumbing_refuses_the_plan() {
        for path in [
            "/",
            "//",
            "///run",
            "/./run",
            "/run",
            "/run/",
            "/run//ukai",
            "/run/./ukai",
            "/run/ukai",
            "/run/ukai/",
            "/run/ukai/jail",
            "/run/ukai/proxy/x.sock",
            "/run/ukai/../ukai",
            "/tmp/../run",
        ] {
            let mut plan = sample_plan();
            plan.masked.push(path.into());
            assert!(
                matches!(plan.render(), Err(PlanError::MaskedBoundaryPlumbing(_))),
                "masking {path} must refuse"
            );
        }
        // A sibling prefix that is not the plumbing still renders.
        let mut plan = sample_plan();
        plan.masked.push("/run/ukai-sibling".into());
        plan.render()
            .expect("/run/ukai-sibling is not boundary plumbing");
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

    #[test]
    fn a_file_mask_requires_an_empty_data_descriptor_and_renders_last() {
        let mut plan = sample_plan();
        plan.extra_ro_binds
            .push(("/private".into(), "/private".into()));
        plan.masked.push(Mask::File("/private/secret".into()));
        assert!(matches!(
            plan.render(),
            Err(PlanError::StagedFdMissing("file denial"))
        ));
        let mut rows = plan.mount_table();
        let mask = rows.last_mut().unwrap();
        assert_eq!(mask.kind, MountKind::FileMask);
        mask.fd = Some(42);
        plan.set_mount_descriptors(rows).unwrap();
        let text = argv_text(&plan);
        assert!(text.contains("--perms 000 --ro-bind-data 42 /private/secret"));
        assert!(
            text.find("--ro-bind /private /private").unwrap()
                < text.find("--ro-bind-data 42 /private/secret").unwrap()
        );
        plan.masked.push(Mask::File("/private/secret/child".into()));
        assert_eq!(
            plan.mount_table()
                .iter()
                .filter(|row| row.kind == MountKind::FileMask)
                .count(),
            1
        );
    }

    /// The descriptors travel with the rows preparation gave them to: a plan
    /// whose table changed afterwards refuses to render rather than hand a
    /// descriptor to whichever row now sits at its position.
    #[test]
    fn descriptors_belong_to_their_rows_not_to_positions() {
        let mut plan = sample_plan();
        let mut rows = plan.mount_table();
        for (index, row) in rows.iter_mut().enumerate() {
            if row.kind.preparation() == MountPreparation::PinSource {
                row.fd = Some(100 + RawFd::try_from(index).unwrap());
            }
        }
        plan.set_mount_descriptors(rows.clone()).unwrap();
        assert_eq!(plan.mount_rows().unwrap(), rows);
        let text = argv_text(&plan);
        let git = rows
            .iter()
            .find(|row| row.destination == "/work/space/.git")
            .unwrap();
        assert!(
            text.contains(&format!(
                "--ro-bind-fd {} /work/space/.git ",
                git.fd.unwrap()
            )),
            "{text}"
        );
        // A row added in front of the pinned ones shifts every position.
        plan.extra_ro_binds.push(("/early".into(), "/early".into()));
        assert!(matches!(plan.render(), Err(PlanError::MountsChanged)));
        // And a table preparation never saw is refused outright.
        let mut other = sample_plan();
        other.extra_ro_binds.push(("/x".into(), "/x".into()));
        assert!(matches!(
            other.set_mount_descriptors(rows),
            Err(PlanError::MountsChanged)
        ));
        // Every kind has one spelling and one preparation.
        for (kind, spelling) in [
            (MountKind::RoBind, "ro-bind"),
            (MountKind::Bind, "bind"),
            (MountKind::Symlink, "symlink"),
            (MountKind::Proc, "proc"),
            (MountKind::Dev, "dev"),
            (MountKind::DevBind, "dev-bind"),
            (MountKind::Cwd, "cwd"),
            (MountKind::Placeholder, "placeholder"),
            (MountKind::VendorState, "vendor-state"),
            (MountKind::Credential, "credential"),
            (MountKind::Proxy, "proxy"),
            (MountKind::TmpfsMask, "tmpfs-mask"),
            (MountKind::FileMask, "file-mask"),
        ] {
            assert_eq!(kind.as_str(), spelling);
        }
    }

    /// The rendered argv, each argument as text.
    fn argv_strings(plan: &BwrapPlan) -> Vec<String> {
        plan.render()
            .unwrap()
            .argv
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    /// The rendered argv joined by spaces, with a trailing space so a
    /// needle can end at an argument's end.
    fn argv_text(plan: &BwrapPlan) -> String {
        let mut text = argv_strings(plan).join(" ");
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
        assert!(at("--ro-bind /usr/local/bin/ukai-jail /run/ukai/jail ") < at("--remount-ro / "));
        assert!(at("--remount-ro / ") < at("--chdir /work/space "));
        assert!(!text.contains("--remount-ro /work/space "));
    }

    #[test]
    fn an_ungranted_workspace_is_a_sealed_empty_tmpfs_above_scratch() {
        let mut plan = sample_plan();
        plan.workspace = PathBuf::from("/tmp/work/space");
        plan.workspace_access = WorkspaceAccess::Hidden;
        plan.extra_ro_binds.clear();
        plan.extra_ro_binds.push((
            PathBuf::from("/tmp/work/space/input"),
            PathBuf::from("/tmp/work/space/input"),
        ));
        let rows = plan.mount_table();
        let index = |path: &str| rows.iter().position(|row| row.destination == path).unwrap();
        assert!(index("/tmp") < index("/tmp/work/space"));
        assert!(index("/tmp/work/space") < index("/tmp/work/space/input"));
        assert_eq!(rows[index("/tmp/work/space")].kind, MountKind::Cwd);
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
        plan.workspace_access = WorkspaceAccess::ReadOnly;
        plan.extra_ro_binds.clear();
        plan.extra_rw_binds.push((
            PathBuf::from("/work/space/out"),
            PathBuf::from("/work/space/out"),
        ));
        let rows = plan.mount_table();
        let index = |path: &str| rows.iter().position(|row| row.destination == path).unwrap();
        assert_eq!(rows[index("/work/space")].kind, MountKind::RoBind);
        assert_eq!(rows[index("/work/space/out")].kind, MountKind::Bind);
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

    /// A plan whose options pass [`ARGS_FD_THRESHOLD`].
    fn long_plan() -> BwrapPlan {
        let mut plan = sample_plan();
        for index in 0..3 {
            plan.set_env(format!("PAD{index}"), "x".repeat(50_000));
        }
        plan
    }

    #[test]
    fn a_long_list_moves_to_the_args_descriptor() {
        let mut plan = long_plan();
        plan.set_args_fd(14);
        let rendered = plan.render().unwrap();
        // The command stays on the command line: bubblewrap 0.11.1 takes only
        // options from the descriptor.
        assert_eq!(rendered.argv[0], OsString::from("bwrap"));
        assert_eq!(rendered.argv[1], OsString::from("--args"));
        assert_eq!(rendered.argv[2], OsString::from("14"));
        assert_eq!(rendered.argv[3], OsString::from("--"));
        assert_eq!(rendered.argv[4], OsString::from("/run/ukai/jail"));
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
        // A short list stays on the command line, descriptor or not.
        let mut plan = sample_plan();
        plan.set_args_fd(14);
        assert!(plan.render().unwrap().args_payload.is_none());
    }

    #[test]
    fn a_long_list_without_a_descriptor_refuses() {
        assert!(matches!(
            long_plan().render(),
            Err(PlanError::ArgsFdMissing)
        ));
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
                "/run/ukai/jail",
            ]
        );
        assert_eq!(rows[1].kind, MountKind::Symlink);
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
    #[test]
    fn staged_vendor_state_and_views_render_by_descriptor_after_every_grant() {
        let mut plan = sample_plan();
        plan.extra_ro_binds = vec![(PathBuf::from("/run"), PathBuf::from("/run"))];
        plan.stage_vendor_state(Staged {
            host: PathBuf::from("/data/attempts/a/vendor-state"),
            fd: 16,
        });
        plan.credential_binds = vec![CredentialBind {
            fd: Some(30),
            destination: PathBuf::from("/run/ukai/state/conf/c.toml"),
        }];
        let argv = argv_strings(&plan);
        let at = |needle: &[&str]| {
            argv.windows(needle.len())
                .position(|window| window == needle)
                .unwrap_or_else(|| panic!("{needle:?} in {argv:?}"))
        };
        let vendor = at(&["--bind-fd", "16", VENDOR_STATE_INSIDE_PATH]);
        let view = at(&["--ro-bind-fd", "30", "/run/ukai/state/conf/c.toml"]);
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
        plan.stage_vendor_state(Staged {
            host: PathBuf::from("/data/attempts/a/vendor-state"),
            fd: 16,
        });
        plan.credential_binds = vec![CredentialBind {
            fd: None,
            destination: PathBuf::from("/run/ukai/state/c"),
        }];
        assert!(matches!(
            plan.render(),
            Err(PlanError::StagedFdMissing("credential"))
        ));
    }
    #[test]
    fn an_argument_carrying_nul_refuses_to_render() {
        let mut plan = sample_plan();
        plan.env.push((
            OsString::from("FIX"),
            OsString::from("x\0--ro-bind\0/secret\0/run/leak"),
        ));
        assert!(matches!(plan.render(), Err(PlanError::ArgumentNul)));
        let mut plan = long_plan();
        plan.env
            .push((OsString::from("A\0--bind\0/\0/x"), OsString::from("v")));
        plan.args_fd = Some(14);
        assert!(matches!(plan.render(), Err(PlanError::ArgumentNul)));
        let mut plan = sample_plan();
        plan.inner.push(OsString::from("tail\0--bind"));
        assert!(matches!(plan.render(), Err(PlanError::ArgumentNul)));
    }

    #[test]
    fn the_proxy_directory_is_bound_read_only_by_descriptor_after_every_grant() {
        let mut plan = sample_plan();
        plan.proxy_dir = Some(Staged {
            host: PathBuf::from("/data/attempts/att_x/proxy"),
            fd: 17,
        });
        let text = argv_text(&plan);
        assert!(
            text.contains(&format!("--ro-bind-fd 17 {PROXY_INSIDE_PATH}")),
            "{text}"
        );
        assert!(
            !text.contains("/data/attempts/att_x/proxy"),
            "the host path never reaches the argv: {text}"
        );
        let proxy_at = text.find(PROXY_INSIDE_PATH).unwrap();
        let jail_at = text.find(JAIL_INSIDE_PATH).unwrap();
        assert!(proxy_at < jail_at, "after every grant, before the binary");
    }
}
