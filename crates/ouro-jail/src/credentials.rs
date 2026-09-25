//! Credential staging into vendor state (jail-v1 §12).
//!
//! Two modes, exactly as §12 defines them:
//!
//! - `copy_rw` takes a point-in-time private copy into vendor state and never
//!   writes anything back. The source is reached through a no-follow walk
//!   from `/`, must be a regular file this operator (or root) owns that no one
//!   else can write, and is read once: the digest is computed from exactly the
//!   bytes written to the copy, and a source that changes while it is read
//!   refuses rather than producing a torn copy. The total copied is bounded by
//!   [`COPY_BUDGET`] per attempt, across every credential; an input that
//!   would exceed it refuses before any byte of it is copied, and in every
//!   case before the target executes.
//! - `bind_ro` exposes the exact granted source file read-only. Staging holds
//!   a descriptor of that exact object (an `O_PATH` handle on Linux) and hands
//!   it to the platform, which binds it with `--ro-bind-fd`, so the object the
//!   checks examined is the object mounted. A source with more than one link
//!   refuses: another name for it could lie where the child can write. Its
//!   digest is recorded only when stable content can be established — the
//!   source lies on a filesystem with no write path at all (squashfs, EROFS,
//!   ISO 9660) and did not change while it was hashed — and is otherwise null
//!   with the reason `source_mutable`: a read-only *mount* of a writable
//!   filesystem does not qualify, because the same inode stays writable
//!   through any other mount.
//!
//! No source may lie inside a child-writable grant: every directory on the
//! no-follow walk and the file itself are compared by identity with the
//! grants the caller names. Nothing here recurses through a directory,
//! follows a symlink or opens a special file for I/O: a FIFO, a socket, a
//! device, a symlink and a directory all refuse, and on Linux they are
//! refused after an `O_PATH` open that has no open-time side effect on the
//! object. Error messages name the logical credential id, never a source
//! path, because errors reach the receipt.
//!
//! [`stage_within`] bounds all of it by a deadline (§8.2's preparation
//! budget): a source on a hung filesystem blocks `read(2)` in a worker
//! thread, not the supervisor, and the attempt refuses when the budget ends.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest as _, Sha256};

use crate::policy::{CredentialDecl, LaunchSnapshot};
use crate::records::{
    CredentialRecord, ErrorCode, ErrorStage, JailError, NativeString, Remediation,
};
use crate::state::anchored::{self, Dir, Kind, Name, Stat};

/// The total `copy_rw` budget per attempt (§12: "16 MiB per attempt").
pub const COPY_BUDGET: u64 = 16 * 1024 * 1024;
/// The largest `bind_ro` source this code will hash for a digest.
pub const DIGEST_BUDGET: u64 = 16 * 1024 * 1024;

/// `copy_rw`.
pub const MODE_COPY_RW: &str = "copy_rw";
/// `bind_ro`.
pub const MODE_BIND_RO: &str = "bind_ro";

/// The bound source can change during the attempt: it is not on a filesystem
/// without a write path, so no digest describes what the child will read.
pub const REASON_SOURCE_MUTABLE: &str = "source_mutable";
/// The bound source changed while it was being hashed.
pub const REASON_SOURCE_CHANGED: &str = "source_changed_while_hashed";
/// The bound source is larger than [`DIGEST_BUDGET`].
pub const REASON_TOO_LARGE: &str = "source_exceeds_digest_budget";

/// A staged source's private identity (kept in jail state, never a receipt).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SourceIdentity {
    /// Device.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// Size at staging.
    pub size: u64,
}

/// One successfully staged credential.
#[derive(Debug)]
pub struct StagedCredential {
    /// The receipt row: `{id, mode, digest, digest_unavailable_reason}`.
    pub record: CredentialRecord,
    /// For `bind_ro`: a descriptor of the exact source object and the
    /// destination relative to vendor state, for `--ro-bind-fd`.
    pub bind: Option<(OwnedFd, NativeString)>,
    /// The source object's identity, for private jail state.
    pub source: SourceIdentity,
}

/// A refused staging: the refusal, and every credential staged before it
/// (§12: "Refusal can report inputs staged before the failure"), whose
/// records reach the receipt and whose identities reach private jail state.
#[derive(Debug)]
pub struct StagingRefusal {
    /// Why staging stopped.
    pub error: JailError,
    /// The credentials staged before it stopped, in id order.
    pub staged: Vec<StagedCredential>,
}

impl StagingRefusal {
    fn bare(error: JailError) -> StagingRefusal {
        StagingRefusal {
            error,
            staged: Vec::new(),
        }
    }

    /// The receipt rows of the credentials staged before the refusal.
    #[must_use]
    pub fn records(&self) -> Vec<CredentialRecord> {
        self.staged.iter().map(|item| item.record.clone()).collect()
    }
}

fn refusal(id: &str, remediation: Remediation, message: impl std::fmt::Display) -> JailError {
    JailError::new(
        ErrorCode::CredentialUnavailable,
        ErrorStage::Preparing,
        remediation,
        format!("credential `{id}`: {message}"),
    )
    .with_key_path(format!("launch.credentials.{id}"))
}

fn state_failure(id: &str, what: &str, error: &std::io::Error) -> JailError {
    JailError::new(
        ErrorCode::StateWriteFailed,
        ErrorStage::Preparing,
        Remediation::InspectState,
        format!("credential `{id}`: vendor state could not be written ({what}: {error})"),
    )
}

/// Stages every credential of `launch` into the vendor-state directory
/// `vendor_state`, after creating its `state_subdirs` (§12).
///
/// `forbidden` holds the `(dev, ino)` identities of every child-writable
/// grant (the workspace, an explicit scratch, every writable host grant); a
/// source whose no-follow walk passes through one of them, or is one of them,
/// refuses. On success every declared credential is staged, in id order. On
/// refusal the credentials staged before the failure come back with it.
///
/// # Errors
/// A [`StagingRefusal`] carrying [`ErrorCode::CredentialUnavailable`] for a
/// missing, special, foreign, shared-writable, multiply-linked (`bind_ro`),
/// oversized, changing or child-writable source, or
/// [`ErrorCode::StateWriteFailed`] when vendor state cannot be written.
pub fn stage(
    launch: &LaunchSnapshot,
    vendor_state: BorrowedFd<'_>,
    forbidden: &[(u64, u64)],
) -> Result<Vec<StagedCredential>, StagingRefusal> {
    stage_reporting(launch, vendor_state, forbidden, &|_| {})
}

/// The longest single wait for the staging worker between two reads of the
/// caller's deadline.
const STAGING_WAIT_STEP: Duration = Duration::from_millis(250);

/// [`stage`] in a worker thread, bounded by the caller's deadline, which
/// `remaining` reads (§6.4: the preparation budget runs on the continuous
/// clock, `CLOCK_BOOTTIME` on Linux).
///
/// A source on a hung filesystem (FUSE, NFS) can block `read(2)`
/// indefinitely. The worker is left behind on expiry: it holds only its own
/// descriptors, and it ends with the process. The refusal then carries the
/// credentials the worker reported staged before the deadline, without their
/// bind descriptors (nothing is bound after a refusal).
///
/// # Errors
/// As [`stage`], plus [`ErrorCode::CredentialUnavailable`] with remediation
/// `retry` when the deadline passes first.
pub fn stage_within(
    launch: &LaunchSnapshot,
    vendor_state: BorrowedFd<'_>,
    forbidden: &[(u64, u64)],
    remaining: &dyn Fn() -> Duration,
) -> Result<Vec<StagedCredential>, StagingRefusal> {
    let vendor = vendor_state
        .try_clone_to_owned()
        .map_err(|error| StagingRefusal::bare(state_failure("*", "descriptor", &error)))?;
    let launch = launch.clone();
    let forbidden = forbidden.to_vec();
    let progress: Arc<Mutex<Vec<(CredentialRecord, SourceIdentity)>>> = Arc::default();
    let report = Arc::clone(&progress);
    let result = within(remaining, move || {
        stage_reporting(&launch, vendor.as_fd(), &forbidden, &|credential| {
            if let Ok(mut staged) = report.lock() {
                staged.push((credential.record.clone(), credential.source));
            }
        })
    });
    match result {
        Some(result) => result,
        None => {
            let staged = progress
                .lock()
                .map(|staged| staged.clone())
                .unwrap_or_default()
                .into_iter()
                .map(|(record, source)| StagedCredential {
                    record,
                    bind: None,
                    source,
                })
                .collect();
            Err(StagingRefusal {
                error: JailError::new(
                    ErrorCode::CredentialUnavailable,
                    ErrorStage::Preparing,
                    Remediation::Retry,
                    "credential staging did not finish within the preparation budget; a \
                     source may be on a filesystem that does not answer"
                        .to_owned(),
                )
                .with_key_path("launch.credentials"),
                staged,
            })
        }
    }
}

/// Runs `work` on a worker thread and waits for it until `remaining` reports
/// no time left.
///
/// `remaining` is read again at least every [`STAGING_WAIT_STEP`]: a
/// `recv_timeout` runs on `CLOCK_MONOTONIC`, which stops during suspend, so a
/// single wait for the whole budget would hold an expired continuous-clock
/// deadline until its own timeout (§6.4). `None` means the deadline came
/// first; the worker keeps running detached and its result is dropped
/// whenever it arrives.
pub fn within<T: Send + 'static>(
    remaining: &dyn Fn() -> Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let spawned = std::thread::Builder::new()
        .name("ouro-jail-staging".to_owned())
        .spawn(move || {
            let _ = sender.send(work());
        });
    if spawned.is_err() {
        return None;
    }
    loop {
        let left = remaining();
        match receiver.recv_timeout(left.min(STAGING_WAIT_STEP)) {
            Ok(value) => return Some(value),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if left.is_zero() => return None,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn stage_reporting(
    launch: &LaunchSnapshot,
    vendor_state: BorrowedFd<'_>,
    forbidden: &[(u64, u64)],
    staged_one: &dyn Fn(&StagedCredential),
) -> Result<Vec<StagedCredential>, StagingRefusal> {
    let vendor = vendor_state
        .try_clone_to_owned()
        .map(Dir::from_owned)
        .map_err(|error| StagingRefusal::bare(state_failure("*", "descriptor", &error)))?;

    let mut subdirs: Vec<&NativeString> = launch.state_subdirs.iter().collect();
    subdirs.sort();
    for subdir in subdirs {
        let components = anchored::split_relative(subdir.as_bytes()).map_err(|error| {
            StagingRefusal::bare(
                JailError::new(
                    ErrorCode::InvalidConfig,
                    ErrorStage::Preparing,
                    Remediation::Configuration,
                    format!("a state subdirectory is not a relative path: {error}"),
                )
                .with_key_path("launch.state_subdirs"),
            )
        })?;
        ensure_directories(&vendor, &components).map_err(|error| {
            StagingRefusal::bare(state_failure("state_subdirs", "create directory", &error))
        })?;
    }

    let mut declarations: Vec<&CredentialDecl> = launch.credentials.iter().collect();
    declarations.sort_by(|left, right| left.id.cmp(&right.id));
    let mut staged: Vec<StagedCredential> = Vec::new();
    let mut copied: u64 = 0;
    for declaration in declarations {
        match stage_one(&vendor, declaration, forbidden, &mut copied) {
            Ok(credential) => {
                staged_one(&credential);
                staged.push(credential);
            }
            Err(error) => return Err(StagingRefusal { error, staged }),
        }
    }
    Ok(staged)
}

/// Walks `components` below `base`, creating each missing directory mode 0700
/// through the anchored handles, and returns the last one.
///
/// A component that already exists must be a directory this operator owns; a
/// symlink or any other object refuses (§12: "A pre-existing symlink or
/// special node refuses").
fn ensure_directories(base: &Dir, components: &[Name]) -> std::io::Result<Dir> {
    let mut current = base.try_clone_fd().map(Dir::from_owned)?;
    for component in components {
        current = match current.stat_at(component) {
            Ok(stat) => {
                if stat.kind != Kind::Directory || stat.uid != crate::state::effective_uid() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("an existing entry is {}", stat.kind.describe()),
                    ));
                }
                current.open_dir_at(component, Some(&stat))?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                current.mkdir_at(component, 0o700)?
            }
            Err(error) => return Err(error),
        };
    }
    Ok(current)
}

/// Whether a `copy_rw` source of `size` bytes still fits the per-attempt
/// budget after `copied` bytes: the budget is one total across every
/// credential of the attempt, never per file.
#[must_use]
pub fn fits_copy_budget(copied: u64, size: u64) -> bool {
    copied
        .checked_add(size)
        .is_some_and(|total| total <= COPY_BUDGET)
}

fn stage_one(
    vendor: &Dir,
    declaration: &CredentialDecl,
    forbidden: &[(u64, u64)],
    copied: &mut u64,
) -> Result<StagedCredential, JailError> {
    let id = declaration.id.as_str();
    let mode = declaration.mode.as_str();
    if mode != MODE_COPY_RW && mode != MODE_BIND_RO {
        return Err(refusal(
            id,
            Remediation::Configuration,
            format!("unknown mode `{mode}`"),
        ));
    }
    let destination = anchored::split_relative(declaration.dest.as_bytes()).map_err(|error| {
        refusal(
            id,
            Remediation::Configuration,
            format!("the destination is not a relative path: {error}"),
        )
    })?;
    let Some((file_name, parents)) = destination.split_last() else {
        return Err(refusal(
            id,
            Remediation::Configuration,
            "the destination is empty",
        ));
    };

    let source = open_source(declaration.source.as_bytes(), forbidden)
        .and_then(|source| check_mode(mode, &source.stat).map(|()| source))
        .map_err(|refused| refused.into_error(id))?;
    let identity = SourceIdentity {
        dev: source.stat.dev,
        ino: source.stat.ino,
        size: source.stat.size,
    };

    if mode == MODE_COPY_RW && !fits_copy_budget(*copied, source.stat.size) {
        return Err(refusal(
            id,
            Remediation::Configuration,
            format!(
                "copying {} more bytes would exceed the {} byte credential-copy budget per \
                 attempt ({} already copied)",
                source.stat.size, COPY_BUDGET, *copied
            ),
        ));
    }

    let parent = ensure_directories(vendor, parents)
        .map_err(|error| state_failure(id, "create directory", &error))?;
    let mut target = parent.create_file_at(file_name, 0o600).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            refusal(
                id,
                Remediation::Configuration,
                "the destination already exists in vendor state",
            )
        } else {
            state_failure(id, "create file", &error)
        }
    })?;

    if mode == MODE_COPY_RW {
        let digest = copy_exactly(id, &source, &mut target)?;
        *copied += source.stat.size;
        return Ok(StagedCredential {
            record: CredentialRecord {
                id: id.to_owned(),
                mode: MODE_COPY_RW.to_owned(),
                digest: Some(digest),
                digest_unavailable_reason: None,
            },
            bind: None,
            source: identity,
        });
    }

    // bind_ro: the empty file just created is the mount point; the source
    // itself is bound over it by descriptor.
    drop(target);
    let (digest, reason) = bind_digest(&source);
    Ok(StagedCredential {
        record: CredentialRecord {
            id: id.to_owned(),
            mode: MODE_BIND_RO.to_owned(),
            digest,
            digest_unavailable_reason: reason.map(str::to_owned),
        },
        bind: Some((source.handle, declaration.dest.clone())),
        source: identity,
    })
}

/// Mode-specific source rules: a `bind_ro` source must have exactly one link.
///
/// The child sees a `bind_ro` source itself, read-only at its view; a second
/// name for the same inode elsewhere (in the workspace, say) would be a
/// writable route to the very file the view claims to pin. A `copy_rw` source
/// is never seen by the child, so its link count does not matter.
fn check_mode(mode: &str, stat: &Stat) -> Result<(), SourceRefusal> {
    if mode == MODE_BIND_RO && stat.nlink != 1 {
        return Err(SourceRefusal::configuration(
            "source_multiply_linked",
            format!(
                "a bind_ro source must have exactly one link, and this one has {}",
                stat.nlink
            ),
        ));
    }
    Ok(())
}

/// An opened credential source: the handle and what `fstat` said about it.
struct Source {
    /// `O_PATH` on Linux; a read descriptor elsewhere.
    handle: OwnedFd,
    stat: Stat,
}

impl Source {
    fn reader(&self) -> std::io::Result<File> {
        #[cfg(target_os = "linux")]
        {
            anchored::reopen_checked(self.handle.as_fd(), &self.stat)
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Not O_PATH here: the handle was opened for reading and is used
            // directly, from its start, exactly once per staging.
            self.handle.try_clone().map(File::from)
        }
    }
}

/// Why a source cannot be staged: a stable reason code for `doctor`, the
/// remediation, and a safe message that names no path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SourceRefusal {
    /// A stable reason code.
    pub reason: &'static str,
    /// What the operator can do about it.
    pub remediation: Remediation,
    /// A safe message: kinds, owners and modes, never a path.
    pub message: String,
}

impl SourceRefusal {
    fn new(reason: &'static str, remediation: Remediation, message: impl Into<String>) -> Self {
        SourceRefusal {
            reason,
            remediation,
            message: message.into(),
        }
    }

    fn configuration(reason: &'static str, message: impl Into<String>) -> Self {
        SourceRefusal::new(reason, Remediation::Configuration, message)
    }

    fn into_error(self, id: &str) -> JailError {
        refusal(id, self.remediation, self.message)
    }
}

/// The identities of every directory on an absolute source path's no-follow
/// walk, then of the file itself, without opening the file.
///
/// Used by resolution to refuse a source inside a child-writable grant before
/// anything is allocated; staging repeats the comparison on its own walk.
///
/// # Errors
/// The [`SourceRefusal`] the walk would produce.
pub fn source_chain(path: &[u8]) -> Result<Vec<(u64, u64)>, SourceRefusal> {
    let walked = walk_to_source(path)?;
    let mut chain = walked.chain;
    chain.push(walked.stat.identity());
    Ok(chain)
}

/// Where a no-follow walk to a source ended.
struct Walked {
    /// The directory holding the final component.
    directory: Dir,
    /// The final component.
    name: Name,
    /// Its `lstat`.
    stat: Stat,
    /// The identities of `/` and every directory walked.
    chain: Vec<(u64, u64)>,
}

/// Walks an absolute source path with no symlink followed.
fn walk_to_source(path: &[u8]) -> Result<Walked, SourceRefusal> {
    let uninspectable = |error: std::io::Error| {
        SourceRefusal::configuration(
            "source_uninspectable",
            format!("the source path cannot be inspected: {error}"),
        )
    };
    let components = anchored::split_absolute(path).map_err(|error| {
        SourceRefusal::configuration(
            "source_path_invalid",
            format!("the source is not an absolute path: {error}"),
        )
    })?;
    let Some((file_name, directories)) = components.split_last() else {
        return Err(SourceRefusal::configuration(
            "source_path_invalid",
            "the source names the filesystem root",
        ));
    };
    let mut current = Dir::open_root_for_walk().map_err(uninspectable)?;
    let root = current.stat().map_err(uninspectable)?;
    check_directory(&root)?;
    let mut chain = vec![root.identity()];
    for component in directories {
        let stat = match current.stat_at(component) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(SourceRefusal::configuration(
                    "source_missing",
                    "the source does not exist",
                ));
            }
            Err(error) => return Err(uninspectable(error)),
        };
        if stat.kind != Kind::Directory {
            return Err(SourceRefusal::configuration(
                "source_path_not_directory",
                format!(
                    "a component of the source path is {}, and a credential path is never \
                     followed through one",
                    stat.kind.describe()
                ),
            ));
        }
        current = current
            .open_walk_at(component, Some(&stat))
            .map_err(uninspectable)?;
        check_directory(&stat)?;
        chain.push(stat.identity());
    }
    let stat = match current.stat_at(file_name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(SourceRefusal::configuration(
                "source_missing",
                "the source does not exist",
            ));
        }
        Err(error) => return Err(uninspectable(error)),
    };
    Ok(Walked {
        directory: current,
        name: file_name.clone(),
        stat,
        chain,
    })
}

/// Refuses a source whose walk passes through, or ends at, a child-writable
/// grant (compared by identity, so no spelling or alias hides it).
fn check_not_in_grant(chain: &[(u64, u64)], forbidden: &[(u64, u64)]) -> Result<(), SourceRefusal> {
    if chain.iter().any(|identity| forbidden.contains(identity)) {
        return Err(SourceRefusal::configuration(
            "source_in_writable_grant",
            "the source lies inside a grant the child can write, so the child could change \
             it",
        ));
    }
    Ok(())
}

/// Opens an absolute source path with a no-follow walk from `/` (§12).
///
/// Every directory on the way is opened relative to the previous one with
/// `O_NOFOLLOW`, checked to be the object `fstatat` described, and must be
/// owned by this operator or root and not writable by anyone else unless it
/// is sticky: a directory someone else can write lets them swap the next
/// component. The final component must be a regular file owned by this
/// operator or root with no group or other write bit, and neither it nor any
/// directory above it may be one of the `forbidden` grants.
fn open_source(path: &[u8], forbidden: &[(u64, u64)]) -> Result<Source, SourceRefusal> {
    let walked = walk_to_source(path)?;
    let mut chain = walked.chain;
    chain.push(walked.stat.identity());
    check_not_in_grant(&chain, forbidden)?;
    let (handle, opened) = open_checked(&walked.directory, &walked.name, &walked.stat)?;
    Ok(Source {
        handle,
        stat: opened,
    })
}

/// The final open of a source: `stat` is what `fstatat` saw; the object
/// actually opened must be that object (a swap between the two refuses) and
/// must itself pass the file checks (a change of kind, owner or mode between
/// the two refuses).
///
/// # Errors
/// The [`SourceRefusal`] for a failed check.
pub fn open_checked(
    directory: &Dir,
    name: &Name,
    stat: &Stat,
) -> Result<(OwnedFd, Stat), SourceRefusal> {
    let uninspectable = |error: std::io::Error| {
        SourceRefusal::configuration(
            "source_uninspectable",
            format!("the source cannot be opened: {error}"),
        )
    };
    check_file(stat)?;
    let handle = open_final(directory, name, stat).map_err(uninspectable)?;
    let opened = anchored::fstat(handle.as_fd()).map_err(uninspectable)?;
    if opened.identity() != stat.identity() {
        return Err(SourceRefusal::new(
            "source_replaced",
            Remediation::Retry,
            "the source was replaced while it was being opened",
        ));
    }
    check_file(&opened)?;
    Ok((handle, opened))
}

#[cfg(target_os = "linux")]
fn open_final(dir: &Dir, name: &Name, _stat: &Stat) -> std::io::Result<OwnedFd> {
    dir.open_path_at(name)
}

#[cfg(not(target_os = "linux"))]
fn open_final(dir: &Dir, name: &Name, _stat: &Stat) -> std::io::Result<OwnedFd> {
    // The identity comparison happens in `open_checked`, on every platform.
    dir.open_read_at(name, None).map(OwnedFd::from)
}

fn check_directory(stat: &Stat) -> Result<(), SourceRefusal> {
    let euid = crate::state::effective_uid();
    if stat.uid != 0 && stat.uid != euid {
        return Err(SourceRefusal::configuration(
            "source_path_foreign_owner",
            format!(
                "a directory on the source path is owned by uid {}, neither root nor this \
                 operator ({euid})",
                stat.uid
            ),
        ));
    }
    if crate::state::writable_by_others(stat.mode, stat.uid, stat.gid) && stat.mode & 0o1000 == 0 {
        return Err(SourceRefusal::configuration(
            "source_path_shared_writable",
            format!(
                "a directory on the source path has mode {:04o}: writable by others without \
                 the sticky bit, so its entries can be replaced",
                stat.mode
            ),
        ));
    }
    Ok(())
}

fn check_file(stat: &Stat) -> Result<(), SourceRefusal> {
    if stat.kind != Kind::Regular {
        return Err(SourceRefusal::configuration(
            "source_not_regular_file",
            format!(
                "the source is {}; only a regular file is staged, and a credential directory \
                 is never recursed",
                stat.kind.describe()
            ),
        ));
    }
    let euid = crate::state::effective_uid();
    if stat.uid != 0 && stat.uid != euid {
        return Err(SourceRefusal::configuration(
            "source_foreign_owner",
            format!(
                "the source is owned by uid {}, neither root nor this operator ({euid})",
                stat.uid
            ),
        ));
    }
    if crate::state::writable_by_others(stat.mode, stat.uid, stat.gid) {
        return Err(SourceRefusal::configuration(
            "source_shared_writable",
            format!(
                "the source has mode {:04o}; a credential others can write is refused",
                stat.mode
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Inspection for `doctor` (§14.1)
// ---------------------------------------------------------------------------

/// One credential as `doctor --launch` reports it: the profile's own names
/// and a status, never a value and never a source path (§14.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CredentialCheck {
    /// The logical id.
    pub id: String,
    /// `copy_rw` or `bind_ro`.
    pub mode: String,
    /// The destination beneath vendor state, as the profile names it.
    pub dest: NativeString,
    /// Whether staging would accept this source now.
    pub available: bool,
    /// `ok` or the stable reason code of the refusal staging would make.
    pub reason_code: &'static str,
}

/// Checks each credential's existence, type, ownership, mode, link count,
/// grant containment and the copy budget exactly as [`stage`] would, without
/// reading content and without writing anything (§14.1). The walk is the
/// same no-follow walk; on Linux the final open is `O_PATH`, so even a special
/// file is never opened for I/O.
#[must_use]
pub fn inspect(launch: &LaunchSnapshot, forbidden: &[(u64, u64)]) -> Vec<CredentialCheck> {
    let mut declarations: Vec<&CredentialDecl> = launch.credentials.iter().collect();
    declarations.sort_by(|left, right| left.id.cmp(&right.id));
    let mut copied: u64 = 0;
    declarations
        .into_iter()
        .map(|declaration| {
            let opened = open_source(declaration.source.as_bytes(), forbidden)
                .and_then(|source| check_mode(&declaration.mode, &source.stat).map(|()| source));
            let reason = match opened {
                Err(refused) => refused.reason,
                Ok(source)
                    if declaration.mode == MODE_COPY_RW
                        && !fits_copy_budget(copied, source.stat.size) =>
                {
                    "copy_budget_exceeded"
                }
                Ok(source) => {
                    if declaration.mode == MODE_COPY_RW {
                        copied += source.stat.size;
                    }
                    "ok"
                }
            };
            CredentialCheck {
                id: declaration.id.clone(),
                mode: declaration.mode.clone(),
                dest: declaration.dest.clone(),
                available: reason == "ok",
                reason_code: reason,
            }
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(7 + bytes.len() * 2);
    out.push_str("sha256:");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Copies the source into `target`, hashing exactly the bytes written.
///
/// The read is bounded by one byte more than the size `fstat` reported, which
/// the caller has already checked against the budget; a source that yields
/// more or fewer bytes than that size, or whose size, times or identity
/// differ afterwards, changed during the copy and refuses. What a refused
/// copy wrote stays in vendor state, which the refusal removes.
fn copy_exactly(id: &str, source: &Source, target: &mut File) -> Result<String, JailError> {
    let expected = source.stat.size;
    let reader = source.reader().map_err(|error| {
        refusal(
            id,
            Remediation::Retry,
            format!("the source cannot be read: {error}"),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut limited = reader.take(expected.saturating_add(1));
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = match limited.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(refusal(
                    id,
                    Remediation::Retry,
                    format!("the source cannot be read: {error}"),
                ));
            }
        };
        total += read as u64;
        let chunk = &buffer[..read];
        hasher.update(chunk);
        target
            .write_all(chunk)
            .map_err(|error| state_failure(id, "write copy", &error))?;
    }
    let after = anchored::fstat(limited.get_ref().as_fd()).map_err(|error| {
        refusal(
            id,
            Remediation::Retry,
            format!("the source cannot be inspected: {error}"),
        )
    })?;
    if !read_was_stable(expected, total, &source.stat, &after) {
        return Err(refusal(
            id,
            Remediation::Retry,
            "the source changed while it was being copied; a point-in-time copy was not \
             established",
        ));
    }
    Ok(hex(&hasher.finalize()))
}

/// Whether one read of a source was a read of stable content: exactly the
/// size `fstat` reported before, and the same object, size and times after.
#[must_use]
pub fn read_was_stable(expected: u64, total: u64, before: &Stat, after: &Stat) -> bool {
    total == expected && after.unchanged_since(before)
}

/// Whether a `bind_ro` digest may be attempted at all: only for a source on
/// a filesystem with no write path, within the digest budget.
///
/// # Errors
/// The reason the digest is unavailable.
pub fn digest_precondition(immutable_filesystem: bool, size: u64) -> Result<(), &'static str> {
    if !immutable_filesystem {
        return Err(REASON_SOURCE_MUTABLE);
    }
    if size > DIGEST_BUDGET {
        return Err(REASON_TOO_LARGE);
    }
    Ok(())
}

/// The digest of a `bind_ro` source, when stable content can be established.
fn bind_digest(source: &Source) -> (Option<String>, Option<&'static str>) {
    let immutable = anchored::immutable_filesystem(source.handle.as_fd()).unwrap_or(false);
    if let Err(reason) = digest_precondition(immutable, source.stat.size) {
        return (None, Some(reason));
    }
    let Ok(reader) = source.reader() else {
        return (None, Some(REASON_SOURCE_CHANGED));
    };
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut limited = reader.take(source.stat.size.saturating_add(1));
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        match limited.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                total += read as u64;
                hasher.update(&buffer[..read]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return (None, Some(REASON_SOURCE_CHANGED)),
        }
    }
    let stable = anchored::fstat(limited.get_ref().as_fd())
        .is_ok_and(|after| read_was_stable(source.stat.size, total, &source.stat, &after));
    if !stable {
        return (None, Some(REASON_SOURCE_CHANGED));
    }
    (Some(hex(&hasher.finalize())), None)
}

// ---------------------------------------------------------------------------
// The hand-off to the platform
// ---------------------------------------------------------------------------

/// The vendor-state directory the supervisor created, for the platform to
/// bind by descriptor (§9.1: pin identity, verify at mount hand-off).
#[derive(Clone)]
pub struct VendorStateHandle {
    /// The host path, for diagnostics only; the bind uses `fd`.
    pub host_path: PathBuf,
    /// A directory descriptor of exactly the registered directory.
    pub fd: Arc<OwnedFd>,
    /// Its `(dev, ino)`.
    pub identity: (u64, u64),
}

/// One `bind_ro` credential, for the platform to bind by descriptor.
#[derive(Clone)]
pub struct BindHandle {
    /// The logical credential id.
    pub id: String,
    /// A descriptor of the exact source object staging examined.
    pub fd: Arc<OwnedFd>,
    /// The destination relative to vendor state.
    pub dest: NativeString,
    /// The source's `(dev, ino)`.
    pub identity: (u64, u64),
}

/// Everything a launch profile hands the platform after staging.
#[derive(Clone, Default)]
pub struct LaunchHandoff {
    /// The vendor-state directory, when the launch profile needs one.
    pub vendor_state: Option<VendorStateHandle>,
    /// The `bind_ro` credentials, in id order.
    pub binds: Vec<BindHandle>,
}

impl LaunchHandoff {
    /// Builds the hand-off from the vendor-state directory and the staged
    /// credentials, moving the bind descriptors out of them.
    ///
    /// # Errors
    /// The errno from `fstat` of the vendor-state directory.
    pub fn new(
        host_path: PathBuf,
        vendor: OwnedFd,
        staged: &mut [StagedCredential],
    ) -> std::io::Result<LaunchHandoff> {
        let identity = anchored::fstat(vendor.as_fd())?.identity();
        let binds = staged
            .iter_mut()
            .filter_map(|credential| {
                let (fd, dest) = credential.bind.take()?;
                Some(BindHandle {
                    id: credential.record.id.clone(),
                    fd: Arc::new(fd),
                    dest,
                    identity: (credential.source.dev, credential.source.ino),
                })
            })
            .collect();
        Ok(LaunchHandoff {
            vendor_state: Some(VendorStateHandle {
                host_path,
                fd: Arc::new(vendor),
                identity,
            }),
            binds,
        })
    }
}

impl PartialEq for LaunchHandoff {
    fn eq(&self, other: &Self) -> bool {
        let vendor = match (&self.vendor_state, &other.vendor_state) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                left.identity == right.identity && left.host_path == right.host_path
            }
            _ => false,
        };
        vendor
            && self.binds.len() == other.binds.len()
            && self.binds.iter().zip(&other.binds).all(|(left, right)| {
                left.id == right.id && left.dest == right.dest && left.identity == right.identity
            })
    }
}

impl Eq for LaunchHandoff {}

impl std::fmt::Debug for LaunchHandoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchHandoff")
            .field(
                "vendor_state",
                &self.vendor_state.as_ref().map(|vendor| vendor.identity),
            )
            .field(
                "binds",
                &self
                    .binds
                    .iter()
                    .map(|bind| (bind.id.as_str(), bind.dest.to_display()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn a_digest_is_the_prefixed_lowercase_hex_the_receipt_schema_requires() {
        let digest = hex(&Sha256::digest(b"abc"));
        assert_eq!(
            digest,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn stat(size: u64, mtime: i64) -> Stat {
        Stat {
            dev: 1,
            ino: 2,
            kind: Kind::Regular,
            mode: 0o600,
            uid: crate::state::effective_uid(),
            gid: 0,
            nlink: 1,
            size,
            mtime: (mtime, 0),
            ctime: (mtime, 0),
            mount_root: None,
        }
    }

    #[test]
    fn a_read_is_stable_only_when_size_count_object_and_times_all_agree() {
        let before = stat(10, 5);
        assert!(read_was_stable(10, 10, &before, &before));
        assert!(!read_was_stable(10, 9, &before, &before), "short read");
        assert!(!read_was_stable(10, 11, &before, &before), "grew");
        assert!(!read_was_stable(10, 10, &before, &stat(10, 6)), "modified");
        assert!(!read_was_stable(10, 10, &before, &stat(11, 5)), "resized");
        let mut other = before;
        other.ino = 3;
        assert!(!read_was_stable(10, 10, &before, &other), "another object");
    }

    #[test]
    fn a_bind_ro_digest_needs_a_filesystem_with_no_write_path() {
        assert_eq!(digest_precondition(false, 1), Err(REASON_SOURCE_MUTABLE));
        assert_eq!(digest_precondition(true, 1), Ok(()));
        assert_eq!(
            digest_precondition(true, DIGEST_BUDGET + 1),
            Err(REASON_TOO_LARGE)
        );
        assert_eq!(REASON_SOURCE_MUTABLE, "source_mutable");
    }

    #[test]
    fn the_copy_budget_is_one_total_per_attempt() {
        assert!(fits_copy_budget(0, COPY_BUDGET));
        assert!(!fits_copy_budget(0, COPY_BUDGET + 1));
        assert!(fits_copy_budget(COPY_BUDGET - 10, 10));
        assert!(!fits_copy_budget(COPY_BUDGET - 10, 11));
        assert!(!fits_copy_budget(u64::MAX, 1), "no overflow into a pass");
    }

    #[test]
    fn a_bind_ro_source_must_have_exactly_one_link() {
        let mut linked = stat(1, 1);
        assert!(check_mode(MODE_BIND_RO, &linked).is_ok());
        linked.nlink = 2;
        assert_eq!(
            check_mode(MODE_BIND_RO, &linked).unwrap_err().reason,
            "source_multiply_linked"
        );
        assert!(
            check_mode(MODE_COPY_RW, &linked).is_ok(),
            "the child never sees a copy_rw source"
        );
    }

    fn directory() -> (tempfile::TempDir, std::path::PathBuf, Dir) {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let handle = Dir::open_trusted(&path).unwrap();
        (dir, path, handle)
    }

    #[test]
    fn a_source_swapped_between_inspection_and_open_is_refused() {
        // J3 review RM12: a real replacement between `fstatat` and the open,
        // done deterministically between the two calls.
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, path, handle) = directory();
        std::fs::write(path.join("token"), b"original").unwrap();
        std::fs::set_permissions(path.join("token"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let name = Name::new(b"token").unwrap();
        let inspected = handle.stat_at(&name).unwrap();
        std::fs::rename(path.join("token"), path.join("moved")).unwrap();
        std::fs::write(path.join("token"), b"impostor").unwrap();
        std::fs::set_permissions(path.join("token"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let refused = open_checked(&handle, &name, &inspected).unwrap_err();
        assert_eq!(refused.reason, "source_replaced");
        assert_eq!(refused.remediation, Remediation::Retry);
    }

    #[test]
    fn a_source_made_shared_writable_between_inspection_and_open_is_refused() {
        // J3 review RM45: same object, but its mode changed after the first
        // check; the opened object is checked again.
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, path, handle) = directory();
        std::fs::write(path.join("token"), b"t").unwrap();
        std::fs::set_permissions(path.join("token"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let name = Name::new(b"token").unwrap();
        let inspected = handle.stat_at(&name).unwrap();
        std::fs::set_permissions(path.join("token"), std::fs::Permissions::from_mode(0o666))
            .unwrap();
        let refused = open_checked(&handle, &name, &inspected).unwrap_err();
        assert_eq!(refused.reason, "source_shared_writable");
        let now = handle.stat_at(&name).unwrap();
        assert_eq!(
            open_checked(&handle, &name, &now).unwrap_err().reason,
            "source_shared_writable"
        );
        std::fs::set_permissions(path.join("token"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let now = handle.stat_at(&name).unwrap();
        assert!(open_checked(&handle, &name, &now).is_ok());
    }

    /// A deadline on the monotonic clock, as the time left on it.
    fn until(deadline: Instant) -> impl Fn() -> Duration {
        move || deadline.saturating_duration_since(Instant::now())
    }

    #[test]
    fn a_wait_ends_when_the_continuous_clock_runs_out_not_the_monotonic_one() {
        // §6.4: the caller's deadline is on the continuous clock, which a
        // suspend advances while the monotonic clock stands still. Here it
        // reports 30 s left, then nothing (a suspend-sized jump), while the
        // worker never finishes: the wait must end within a step of the jump,
        // not after the 30 s it was first given.
        let reads = std::sync::atomic::AtomicUsize::new(0);
        let remaining = || {
            if reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Duration::from_secs(30)
            } else {
                Duration::ZERO
            }
        };
        let (_hold, blocked) = std::sync::mpsc::channel::<()>();
        let started = Instant::now();
        let result = within(&remaining, move || blocked.recv().is_ok());
        let waited = started.elapsed();
        assert_eq!(result, None);
        assert!(
            waited < Duration::from_secs(5),
            "the wait held a deadline the continuous clock had passed: {waited:?}"
        );
        assert!(reads.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    }

    #[test]
    fn work_past_its_deadline_is_abandoned_and_finishes_harmlessly_later() {
        // The budget path of `stage_within` (J3 review L4), with a source that
        // blocks until released: a closure blocked on a channel.
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let (done, finished) = std::sync::mpsc::channel::<()>();
        let started = Instant::now();
        let result = within(
            &until(Instant::now() + std::time::Duration::from_millis(150)),
            move || {
                let _ = blocked.recv();
                let _ = done.send(());
                "staged"
            },
        );
        assert_eq!(result, None);
        let waited = started.elapsed();
        assert!(
            waited >= std::time::Duration::from_millis(150),
            "{waited:?}"
        );
        assert!(waited < std::time::Duration::from_secs(5), "{waited:?}");
        release.send(()).unwrap();
        finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the abandoned worker still finishes");
        assert_eq!(
            within(
                &until(Instant::now() + std::time::Duration::from_secs(5)),
                || 7
            ),
            Some(7)
        );
    }

    #[test]
    fn stage_within_stages_inside_its_budget_and_refuses_past_it() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, path, handle) = directory();
        for name in ["a", "b"] {
            std::fs::write(path.join(name), name).unwrap();
            std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let vendor = handle.mkdir_at(&Name::new(b"vs").unwrap(), 0o700).unwrap();
        let launch = LaunchSnapshot {
            state_var: None,
            home_is_state: false,
            state_subdirs: Vec::new(),
            credentials: ["a", "b"]
                .iter()
                .map(|id| CredentialDecl {
                    id: (*id).to_owned(),
                    source: NativeString::from_bytes(
                        path.join(id).as_os_str().as_encoded_bytes().to_vec(),
                    )
                    .unwrap(),
                    dest: NativeString::Text((*id).to_owned()),
                    mode: MODE_COPY_RW.to_owned(),
                })
                .collect(),
        };
        let staged = stage_within(
            &launch,
            vendor.as_fd(),
            &[],
            &until(Instant::now() + std::time::Duration::from_secs(10)),
        )
        .expect("within a generous budget");
        assert_eq!(staged.len(), 2);
        let expired = stage_within(&launch, vendor.as_fd(), &[], &|| Duration::ZERO);
        match expired {
            Err(refusal) if refusal.error.remediation == Remediation::Retry => {
                assert_eq!(refusal.error.code, ErrorCode::CredentialUnavailable);
            }
            // The worker can finish in the instant before the wait: then the
            // destinations already exist, which is its own refusal.
            Err(refusal) => assert!(refusal.error.message.contains("already exists")),
            Ok(_) => panic!("the destinations exist; staging again cannot succeed"),
        }
    }
}
