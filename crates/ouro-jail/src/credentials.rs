//! Credential staging into vendor state (jail-v1 §12).
//!
//! Two staging modes, exactly as §12 defines them, and `vault`, which stages
//! nothing (below):
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
//! - `vault` puts no file in vendor state. The source passes the same walk
//!   and file checks, and the supervisor then reads it live, owner-only and
//!   bounded by [`crate::vault::SOURCE_MAX`], for the egress proxy to place
//!   (`crate::vault`).
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
use std::sync::atomic::{AtomicBool, Ordering};
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
/// `vault`.
pub const MODE_VAULT: &str = "vault";

/// `doctor`'s reason for a `vault` credential that passes every check staging
/// makes before it reads the secret. `doctor` reads no credential, so the
/// value (or refresh document) and the bound executables are checked only
/// when staging reads them.
pub const REASON_VALUE_UNREAD: &str = "value_unread";

/// The read buffer for one source; credential bytes pass through it, so it
/// is zeroized when dropped.
const READ_CHUNK: usize = 64 * 1024;

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
    pub vault: Option<Arc<crate::vault::Secret>>,
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
/// missing, special, foreign, shared-writable, multiply-linked (either mode,
/// security 2026-09-25), oversized, changing or child-writable source, or
/// [`ErrorCode::StateWriteFailed`] when vendor state cannot be written.
pub fn stage(
    launch: &LaunchSnapshot,
    vendor_state: BorrowedFd<'_>,
    forbidden: &[(u64, u64)],
) -> Result<Vec<StagedCredential>, StagingRefusal> {
    stage_reporting(launch, vendor_state, forbidden, &|_| {}, &|| false)
}

/// The longest single wait for the staging worker between two reads of the
/// caller's deadline.
const STAGING_WAIT_STEP: Duration = Duration::from_millis(250);

/// [`stage`] in a worker thread, bounded by the caller's deadline, which
/// `remaining` reads (§6.4: the preparation budget runs on the continuous
/// clock, `CLOCK_BOOTTIME` on Linux).
///
/// A source on a hung filesystem (FUSE, NFS) can block `open(2)` or
/// `read(2)` indefinitely. The worker is left behind on expiry, holding only
/// its own descriptors until it ends with the process. It is told it was
/// abandoned and checks before every further state directory and
/// credential, and again once a credential's source is open, so the only
/// work between its last check and a create is in vendor state itself (the
/// target's parent directories and the empty target), never on the source.
/// The refusal carries exactly the credentials it reported staged before
/// then, without their bind descriptors (nothing is bound after a refusal).
/// A copy it was already writing at expiry may still complete; it is never
/// reported staged, and its target file is in vendor state, which the
/// refusal's cleanup removes, after which the worker writes only to the
/// removed file. An entry the worker creates after its last check is removed
/// the same way, or, if it appears while cleanup walks the directory, leaves
/// the cleanup `pending` for `gc`.
///
/// # Errors
/// As [`stage`], plus [`ErrorCode::CredentialUnavailable`] with remediation
/// `retry` when the deadline passes first or the worker thread cannot be
/// started, and [`ErrorCode::InternalError`] when the worker ends without a
/// result.
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
    let progress = Arc::new(Progress::default());
    let worker = Arc::clone(&progress);
    let result = within(remaining, move || {
        stage_reporting(
            &launch,
            vendor.as_fd(),
            &forbidden,
            &|credential| worker.report(credential),
            &|| worker.abandoned(),
        )
    });
    let error = match result {
        Ok(result) => return result,
        Err(Abandoned::Deadline) => JailError::new(
            ErrorCode::CredentialUnavailable,
            ErrorStage::Preparing,
            Remediation::Retry,
            "credential staging did not finish within the preparation budget; a source may be \
             on a filesystem that does not answer"
                .to_owned(),
        ),
        Err(Abandoned::Spawn(error)) => JailError::new(
            ErrorCode::CredentialUnavailable,
            ErrorStage::Preparing,
            Remediation::Retry,
            format!("credential staging could not start its worker thread: {error}"),
        ),
        Err(Abandoned::Lost) => JailError::new(
            ErrorCode::InternalError,
            ErrorStage::Preparing,
            Remediation::InspectState,
            "the credential staging worker ended without a result".to_owned(),
        ),
    }
    .with_key_path("launch.credentials");
    Err(StagingRefusal {
        error,
        staged: progress
            .abandon()
            .into_iter()
            .map(|(record, source)| StagedCredential {
                vault: None,
                record,
                bind: None,
                source,
            })
            .collect(),
    })
}

/// What a staging worker has reported staged, and whether its caller has
/// given up on it. One lock orders the two: a credential is either in the
/// list [`Progress::abandon`] returns or never recorded at all.
#[derive(Default)]
struct Progress {
    staged: Mutex<Vec<(CredentialRecord, SourceIdentity)>>,
    abandoned: AtomicBool,
}

impl Progress {
    /// Records a staged credential, unless the caller has given up.
    fn report(&self, credential: &StagedCredential) {
        let mut staged = crate::sync::lock(&self.staged);
        if !self.abandoned.load(Ordering::SeqCst) {
            staged.push((credential.record.clone(), credential.source));
        }
    }

    /// Whether the caller has given up on the worker.
    fn abandoned(&self) -> bool {
        self.abandoned.load(Ordering::SeqCst)
    }

    /// Gives up on the worker and returns what it reported before then;
    /// nothing it reports afterwards is recorded.
    fn abandon(&self) -> Vec<(CredentialRecord, SourceIdentity)> {
        let staged = crate::sync::lock(&self.staged);
        self.abandoned.store(true, Ordering::SeqCst);
        staged.clone()
    }
}

/// Why [`within`] has no result.
#[derive(Debug)]
enum Abandoned {
    /// The worker thread could not be started, so nothing ran.
    Spawn(std::io::Error),
    /// The deadline came first; the worker runs on, detached.
    Deadline,
    /// The worker ended without sending a result: it panicked.
    Lost,
}

/// Runs `work` on a worker thread and waits for it until `remaining` reports
/// no time left.
///
/// `remaining` is read again at least every [`STAGING_WAIT_STEP`]: a
/// `recv_timeout` runs on `CLOCK_MONOTONIC`, which stops during suspend, so a
/// single wait for the whole budget would hold an expired continuous-clock
/// deadline until its own timeout (§6.4). After [`Abandoned::Deadline`] the
/// worker keeps running detached and its result is dropped whenever it
/// arrives.
fn within<T: Send + 'static>(
    remaining: &dyn Fn() -> Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Abandoned> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("ouro-jail-staging".to_owned())
        .spawn(move || {
            let _ = sender.send(work());
        })
        .map_err(Abandoned::Spawn)?;
    loop {
        let left = remaining();
        match receiver.recv_timeout(left.min(STAGING_WAIT_STEP)) {
            Ok(value) => return Ok(value),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err(Abandoned::Lost),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if left.is_zero() => {
                return Err(Abandoned::Deadline);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

/// The refusal of a worker that finds it was abandoned.
fn abandoned_error() -> JailError {
    JailError::new(
        ErrorCode::CredentialUnavailable,
        ErrorStage::Preparing,
        Remediation::Retry,
        "credential staging was abandoned at its deadline".to_owned(),
    )
    .with_key_path("launch.credentials")
}

/// Stages `launch` in id order, reporting each credential once it is staged,
/// and stops before the next state directory or credential, or before
/// creating a credential's target, once `abandoned` says so (as
/// [`stage_within`] does at its deadline).
fn stage_reporting(
    launch: &LaunchSnapshot,
    vendor_state: BorrowedFd<'_>,
    forbidden: &[(u64, u64)],
    staged_one: &dyn Fn(&StagedCredential),
    abandoned: &dyn Fn() -> bool,
) -> Result<Vec<StagedCredential>, StagingRefusal> {
    let vendor = vendor_state
        .try_clone_to_owned()
        .map(Dir::from_owned)
        .map_err(|error| StagingRefusal::bare(state_failure("*", "descriptor", &error)))?;

    let mut subdirs: Vec<&NativeString> = launch.state_subdirs.iter().collect();
    subdirs.sort();
    for subdir in subdirs {
        if abandoned() {
            return Err(StagingRefusal::bare(abandoned_error()));
        }
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
        if abandoned() {
            return Err(StagingRefusal {
                error: abandoned_error(),
                staged,
            });
        }
        match stage_one(&vendor, declaration, forbidden, &mut copied, abandoned) {
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

/// Stages one credential. `abandoned` is asked again once the source is
/// open, just before the target's directories and file are created: opening
/// a source on a hung filesystem can outlast the caller's deadline.
fn stage_one(
    vendor: &Dir,
    declaration: &CredentialDecl,
    forbidden: &[(u64, u64)],
    copied: &mut u64,
    abandoned: &dyn Fn() -> bool,
) -> Result<StagedCredential, JailError> {
    let id = declaration.id.as_str();
    let mode = declaration.mode.as_str();
    if mode != MODE_COPY_RW && mode != MODE_BIND_RO && mode != MODE_VAULT {
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
        .and_then(|source| check_mode(&source.stat).map(|()| source))
        .map_err(|refused| refused.into_error(id))?;
    let identity = SourceIdentity {
        dev: source.stat.dev,
        ino: source.stat.ino,
        size: source.stat.size,
    };

    if mode == MODE_VAULT {
        let policy = declaration
            .vault
            .clone()
            .ok_or_else(|| refusal(id, Remediation::Configuration, "vault policy absent"))?;
        let secret = crate::vault::Secret::from_source(
            id.to_owned(),
            policy,
            declaration.source.as_bytes().to_vec(),
            forbidden.to_vec(),
        )
        .map_err(|e| refusal(id, Remediation::Configuration, e))?;
        return Ok(StagedCredential {
            vault: Some(Arc::new(secret)),
            record: CredentialRecord {
                never_staged: true,
                id: id.into(),
                mode: MODE_VAULT.into(),
                digest: None,
                digest_unavailable_reason: Some("never_staged".into()),
            },
            bind: None,
            source: identity,
        });
    }

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

    if abandoned() {
        return Err(abandoned_error());
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
            vault: None,
            record: CredentialRecord {
                never_staged: false,
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
        vault: None,
        record: CredentialRecord {
            never_staged: false,
            id: id.to_owned(),
            mode: MODE_BIND_RO.to_owned(),
            digest,
            digest_unavailable_reason: reason.map(str::to_owned),
        },
        bind: Some((source.handle, declaration.dest.clone())),
        source: identity,
    })
}

/// Stable, bounded no-follow re-read for a live vault source. Errors carry
/// only safe reason codes; source paths and credential bytes never escape.
pub(crate) fn read_vault_source(
    path: &[u8],
    forbidden: &[(u64, u64)],
    max: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, &'static str> {
    read_vault_source_version(path, forbidden, max).map(|(bytes, _)| bytes)
}

pub(crate) fn read_vault_source_version(
    path: &[u8],
    forbidden: &[(u64, u64)],
    max: usize,
) -> Result<(zeroize::Zeroizing<Vec<u8>>, Stat), &'static str> {
    let source = open_source(path, forbidden).map_err(|_| "source_unavailable")?;
    check_mode(&source.stat).map_err(|_| "source_unsafe")?;
    vault_precheck(&source.stat, max)?;
    // `max + 1` holds whatever a stable read can return (`size <= max`, plus
    // the one byte that shows growth), so the vector never reallocates and
    // leaves no unzeroized copy of the secret behind.
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(max + 1));
    let after = read_stable(&source, &mut |chunk| {
        bytes.extend_from_slice(chunk);
        Ok(())
    })
    .map_err(|failure| match failure {
        ReadFailure::Changed => "source_changed",
        ReadFailure::Read(_) | ReadFailure::Sink(_) | ReadFailure::Inspect(_) => {
            "source_unavailable"
        }
    })?;
    Ok((bytes, after))
}

/// The checks a `vault` source must pass before any byte of it is read: no
/// group or other permission at all, and at most `max` bytes. One function
/// for staging (through [`read_vault_source_version`]) and for `doctor`
/// ([`inspect`]), so the two cannot disagree.
fn vault_precheck(stat: &Stat, max: usize) -> Result<(), &'static str> {
    if stat.mode & 0o077 != 0 {
        return Err("source_not_private");
    }
    if stat.size > max as u64 {
        return Err("source_oversized");
    }
    Ok(())
}

/// Serialize a private source update across attempts, without recreating a
/// deleted/replaced source. The held descriptor pins the checked inode; the
/// final path and complete expected content are revalidated under the lock.
#[cfg(target_os = "linux")]
pub(crate) fn update_vault_source(
    path: &[u8],
    forbidden: &[(u64, u64)],
    expected: &[u8],
    expected_identity: (u64, u64),
    replacement: &[u8],
) -> Result<(), &'static str> {
    use std::io::{Seek as _, SeekFrom};
    let source = open_source(path, forbidden).map_err(|_| "source_unavailable")?;
    check_mode(&source.stat).map_err(|_| "source_unsafe")?;
    if source.stat.identity() != expected_identity {
        return Err("source_changed");
    }
    if source.stat.uid != crate::state::effective_uid() || source.stat.mode & 0o077 != 0 {
        return Err("refresh_source_not_private");
    }
    let walked = walk_to_source(path).map_err(|_| "source_unavailable")?;
    let mut file = anchored::reopen_write_checked(source.handle.as_fd(), &source.stat)
        .map_err(|_| "source_unavailable")?;
    let stat = anchored::fstat(file.as_fd()).map_err(|_| "source_unavailable")?;
    if stat.identity() != source.stat.identity() {
        return Err("source_changed");
    }
    use std::os::fd::AsRawFd as _;
    // SAFETY: file is a live, exclusively owned descriptor; LOCK_NB never
    // lets an operator or another attempt stall this request indefinitely.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("refresh_busy");
    }
    let max = crate::vault::SOURCE_MAX;
    let mut current = zeroize::Zeroizing::new(Vec::with_capacity(max + 1));
    (&mut file)
        .take(max as u64 + 1)
        .read_to_end(&mut current)
        .map_err(|_| "source_unavailable")?;
    if current.as_slice() != expected || replacement.len() > max {
        return Err("source_changed");
    }
    let now = walked
        .directory
        .stat_at(&walked.name)
        .map_err(|_| "source_changed")?;
    if now.identity() != stat.identity() {
        return Err("source_changed");
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "source_update_failed")?;
    file.write_all(replacement)
        .map_err(|_| "source_update_failed")?;
    file.set_len(replacement.len() as u64)
        .map_err(|_| "source_update_failed")?;
    file.sync_all().map_err(|_| "source_update_failed")?;
    let final_stat = walked
        .directory
        .stat_at(&walked.name)
        .map_err(|_| "source_changed")?;
    if final_stat.identity() != stat.identity() {
        return Err("source_changed");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn update_vault_source(
    _path: &[u8],
    _forbidden: &[(u64, u64)],
    _expected: &[u8],
    _expected_identity: (u64, u64),
    _replacement: &[u8],
) -> Result<(), &'static str> {
    Err("refresh_requires_linux")
}

/// Mode-specific source rules: a source must have exactly one link.
///
/// A `bind_ro` source is seen by the child itself, read-only at its view; a
/// second name for the same inode elsewhere (in the workspace, say) would be
/// a writable route to the very file the view claims to pin. Security
/// 2026-09-25 (audit F5): a `copy_rw` source refuses a second link too. The
/// copy itself is never seen by the child, but a second name is another
/// writer into what is being copied, and the staging's stable-copy check
/// then has a race to win rather than an invariant to hold: one named
/// object, one content, one digest.
fn check_mode(stat: &Stat) -> Result<(), SourceRefusal> {
    if stat.nlink != 1 {
        return Err(SourceRefusal::configuration(
            "source_multiply_linked",
            format!(
                "a credential source must have exactly one link, and this one has {}",
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
    /// `copy_rw`, `bind_ro` or `vault`.
    pub mode: String,
    /// The destination beneath vendor state, as the profile names it.
    pub dest: NativeString,
    /// Whether every check [`inspect`] makes passed. For `copy_rw` and
    /// `bind_ro` those are all the checks staging makes before it reads; see
    /// `reason_code` for `vault`.
    pub available: bool,
    /// `ok`; [`REASON_VALUE_UNREAD`] for a `vault` source that passed every
    /// check before its value is read; or the stable reason code of the
    /// refusal staging would make.
    pub reason_code: &'static str,
}

/// Checks each credential's existence, type, ownership, mode, link count,
/// grant containment and the copy budget as [`stage`] does, and for `vault`
/// the owner-only mode and size bound staging checks before it reads the
/// secret ([`vault_precheck`], shared), without reading content and without
/// writing anything (§14.1). The walk is the same no-follow walk; on Linux the
/// final open is `O_PATH`, so even a special file is never opened for I/O.
///
/// What only a read can establish is not claimed: a copy that changes while
/// it is copied, and for `vault` the value itself, its refresh document and
/// the pins of its bound executables, which is why a `vault` source that
/// passes reports [`REASON_VALUE_UNREAD`] rather than `ok`.
#[must_use]
pub fn inspect(launch: &LaunchSnapshot, forbidden: &[(u64, u64)]) -> Vec<CredentialCheck> {
    let mut declarations: Vec<&CredentialDecl> = launch.credentials.iter().collect();
    declarations.sort_by(|left, right| left.id.cmp(&right.id));
    let mut copied: u64 = 0;
    declarations
        .into_iter()
        .map(|declaration| {
            let opened = open_source(declaration.source.as_bytes(), forbidden)
                .and_then(|source| check_mode(&source.stat).map(|()| source));
            let reason = match opened {
                Err(refused) => refused.reason,
                Ok(source) if declaration.mode == MODE_VAULT => {
                    match vault_precheck(&source.stat, crate::vault::SOURCE_MAX) {
                        Ok(()) => REASON_VALUE_UNREAD,
                        Err(reason) => reason,
                    }
                }
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
                available: reason == "ok" || reason == REASON_VALUE_UNREAD,
                reason_code: reason,
            }
        })
        .collect()
}

/// `sha256:` and the lowercase hex of a finished SHA-256: the spelling of
/// [`crate::canonical::sha256_prefixed`], which hashes a whole buffer where
/// the copy here hashes a stream.
fn prefixed_hex(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Why one bounded read of a source failed.
enum ReadFailure {
    /// The source could not be opened for reading or read.
    Read(std::io::Error),
    /// The sink refused a chunk.
    Sink(std::io::Error),
    /// The source could not be inspected after the read.
    Inspect(std::io::Error),
    /// The bytes read are not the stable content `fstat` described.
    Changed,
}

/// Reads a source's content once, handing every chunk to `sink`.
///
/// The read is bounded by one byte more than the size `fstat` reported, which
/// the caller has already checked against its budget; a source that yields
/// more or fewer bytes than that size, or whose size, times or identity differ
/// afterwards, changed during the read ([`read_was_stable`]). Returns the
/// source's `fstat` after the read. One implementation for the `copy_rw`
/// copy, the `bind_ro` digest and the live `vault` read.
fn read_stable(
    source: &Source,
    sink: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<Stat, ReadFailure> {
    let reader = source.reader().map_err(ReadFailure::Read)?;
    let mut limited = reader.take(source.stat.size.saturating_add(1));
    let mut buffer = zeroize::Zeroizing::new(vec![0u8; READ_CHUNK]);
    let mut total: u64 = 0;
    loop {
        let read = match limited.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ReadFailure::Read(error)),
        };
        total += read as u64;
        sink(&buffer[..read]).map_err(ReadFailure::Sink)?;
    }
    let after = anchored::fstat(limited.get_ref().as_fd()).map_err(ReadFailure::Inspect)?;
    if !read_was_stable(source.stat.size, total, &source.stat, &after) {
        return Err(ReadFailure::Changed);
    }
    Ok(after)
}

/// Copies the source into `target`, hashing exactly the bytes written
/// ([`read_stable`]). What a refused copy wrote stays in vendor state, which
/// the refusal removes.
fn copy_exactly(id: &str, source: &Source, target: &mut File) -> Result<String, JailError> {
    let mut hasher = Sha256::new();
    read_stable(source, &mut |chunk| {
        hasher.update(chunk);
        target.write_all(chunk)
    })
    .map_err(|failure| match failure {
        ReadFailure::Read(error) => refusal(
            id,
            Remediation::Retry,
            format!("the source cannot be read: {error}"),
        ),
        ReadFailure::Sink(error) => state_failure(id, "write copy", &error),
        ReadFailure::Inspect(error) => refusal(
            id,
            Remediation::Retry,
            format!("the source cannot be inspected: {error}"),
        ),
        ReadFailure::Changed => refusal(
            id,
            Remediation::Retry,
            "the source changed while it was being copied; a point-in-time copy was not \
             established",
        ),
    })?;
    Ok(prefixed_hex(&hasher.finalize()))
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
    let mut hasher = Sha256::new();
    match read_stable(source, &mut |chunk| {
        hasher.update(chunk);
        Ok(())
    }) {
        Ok(_) => (Some(prefixed_hex(&hasher.finalize())), None),
        Err(_) => (None, Some(REASON_SOURCE_CHANGED)),
    }
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
    pub vault: Vec<Arc<crate::vault::Secret>>,
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
            vault: staged.iter().filter_map(|c| c.vault.clone()).collect(),
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
            && self
                .vault
                .iter()
                .map(|s| &s.id)
                .eq(other.vault.iter().map(|s| &s.id))
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
        let digest = prefixed_hex(&Sha256::digest(b"abc"));
        assert_eq!(
            digest,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(digest, crate::canonical::sha256_prefixed(b"abc"));
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
    fn a_credential_source_must_have_exactly_one_link() {
        let mut linked = stat(1, 1);
        assert!(check_mode(&linked).is_ok());
        linked.nlink = 2;
        assert_eq!(
            check_mode(&linked).unwrap_err().reason,
            "source_multiply_linked"
        );
    }

    /// Security 2026-09-25 (audit F5): the one-link rule holds for every
    /// mode. A second name is another writer into what is being copied or
    /// pinned; `copy_rw` does not rely on the child not seeing the source.
    #[test]
    fn every_mode_refuses_a_multiply_linked_source() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, path, _handle) = directory();
        std::fs::write(path.join("token"), b"t").unwrap();
        std::fs::set_permissions(path.join("token"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        std::fs::hard_link(path.join("token"), path.join("alias")).unwrap();
        let source =
            NativeString::from_bytes(path.join("token").as_os_str().as_encoded_bytes().to_vec())
                .unwrap();
        let launch = LaunchSnapshot {
            state_var: None,
            home_is_state: false,
            state_subdirs: Vec::new(),
            credentials: [MODE_COPY_RW, MODE_BIND_RO, MODE_VAULT]
                .iter()
                .map(|mode| CredentialDecl {
                    vault: None,
                    id: (*mode).to_owned(),
                    source: source.clone(),
                    dest: NativeString::Text((*mode).to_owned()),
                    mode: (*mode).to_owned(),
                })
                .collect(),
        };
        for check in inspect(&launch, &[]) {
            assert_eq!(
                check.reason_code, "source_multiply_linked",
                "{}",
                check.mode
            );
        }
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

    /// `doctor` runs the same pre-read checks staging runs for a `vault`
    /// source, so a source staging would refuse as group-readable or
    /// oversized is not reported available; one that passes them says its
    /// value was not read rather than `ok`. Each verdict is held to the real
    /// staging call (`stage_one`, which reads the source through the vault
    /// runtime), not to a read the test makes with a bound of its choosing:
    /// two refresh documents of exactly [`crate::vault::SOURCE_MAX`] bytes
    /// and one byte more pin the bound staging uses to the one doctor
    /// reports.
    #[test]
    fn doctor_applies_the_vault_precheck_staging_applies() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, path, handle) = directory();
        let write = |name: &str, bytes: &[u8], mode: u32| {
            std::fs::write(path.join(name), bytes).unwrap();
            std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(mode))
                .unwrap();
            NativeString::from_bytes(path.join(name).as_os_str().as_encoded_bytes().to_vec())
                .unwrap()
        };
        // A refresh document that is valid for a month, padded with JSON
        // whitespace to `size` bytes: staging reads it whole and needs no
        // token exchange.
        let document = |size: usize| {
            let expires = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 30 * 24 * 60 * 60;
            let mut text = format!(
                r#"{{"access_token":"access","refresh_token":"refresh","expires_at":{expires}}}"#
            )
            .into_bytes();
            text.resize(size, b' ');
            text
        };
        let refresh = crate::vault::RefreshPolicy {
            token_url: "https://issuer.example.com/token".to_owned(),
            client_id: "fixture".to_owned(),
            refresh_before_seconds: 0,
            encoding: crate::vault::TokenEncoding::Form,
        };
        let declaration = |id: &str, source: NativeString, refreshes: bool| CredentialDecl {
            vault: Some(crate::vault::Policy {
                hosts: vec!["https://api.example.com".to_owned()],
                refresh: refreshes.then(|| refresh.clone()),
                ..crate::vault::Policy::default()
            }),
            id: id.to_owned(),
            source,
            dest: NativeString::Text(format!(".vault-{id}")),
            mode: MODE_VAULT.to_owned(),
        };
        let max = crate::vault::SOURCE_MAX;
        let cases = [
            (
                declaration("group", write("group", b"key", 0o640), false),
                "source_not_private",
            ),
            (
                declaration("large", write("large", &document(max + 1), 0o600), true),
                "source_oversized",
            ),
            (
                declaration("largest", write("largest", &document(max), 0o600), true),
                REASON_VALUE_UNREAD,
            ),
            (
                declaration("private", write("private", b"key", 0o600), false),
                REASON_VALUE_UNREAD,
            ),
        ];
        let launch = LaunchSnapshot {
            state_var: None,
            home_is_state: false,
            state_subdirs: Vec::new(),
            credentials: cases
                .iter()
                .map(|(declaration, _)| declaration.clone())
                .collect(),
        };
        let checks = inspect(&launch, &[]);
        assert_eq!(checks.len(), cases.len());
        for ((declaration, reason), check) in cases.iter().zip(&checks) {
            let id = declaration.id.as_str();
            assert_eq!((check.id.as_str(), check.reason_code), (id, *reason));
            assert_eq!(check.available, *reason == REASON_VALUE_UNREAD, "{id}");
            let staged = stage_one(&handle, declaration, &[], &mut 0, &|| false);
            assert_eq!(
                staged.is_ok(),
                check.available,
                "{id}: staging agrees with doctor ({:?})",
                staged.err().map(|error| error.message)
            );
        }
    }

    /// Once `stage_within` has given up on its worker, the worker starts no
    /// further state directory or credential, so nothing is staged that the
    /// refusal does not list.
    #[test]
    fn an_abandoned_worker_stages_nothing_further() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, path, handle) = directory();
        std::fs::write(path.join("a"), b"a").unwrap();
        std::fs::set_permissions(path.join("a"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let vendor = handle.mkdir_at(&Name::new(b"vs").unwrap(), 0o700).unwrap();
        let launch = LaunchSnapshot {
            state_var: None,
            home_is_state: false,
            state_subdirs: vec![NativeString::Text("cache".to_owned())],
            credentials: vec![CredentialDecl {
                vault: None,
                id: "a".to_owned(),
                source: NativeString::from_bytes(
                    path.join("a").as_os_str().as_encoded_bytes().to_vec(),
                )
                .unwrap(),
                dest: NativeString::Text("a".to_owned()),
                mode: MODE_COPY_RW.to_owned(),
            }],
        };
        let reported = Mutex::new(0usize);
        let refused = stage_reporting(
            &launch,
            vendor.as_fd(),
            &[],
            &|_| *reported.lock().unwrap() += 1,
            &|| true,
        )
        .expect_err("an abandoned worker stops");
        assert!(refused.staged.is_empty());
        assert_eq!(*reported.lock().unwrap(), 0);
        assert!(std::fs::read_dir(path.join("vs")).unwrap().next().is_none());
    }

    /// One `copy_rw` credential per id, each sourced from a private file of
    /// that name, and no state subdirectory: the per-credential checks are
    /// the first an abandoned worker meets.
    fn copies(path: &std::path::Path, ids: &[&str]) -> LaunchSnapshot {
        use std::os::unix::fs::PermissionsExt as _;
        LaunchSnapshot {
            state_var: None,
            home_is_state: false,
            state_subdirs: Vec::new(),
            credentials: ids
                .iter()
                .map(|id| {
                    let source = path.join(id);
                    if std::fs::write(&source, id.as_bytes()).is_ok() {
                        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600))
                            .unwrap();
                    }
                    CredentialDecl {
                        vault: None,
                        id: (*id).to_owned(),
                        source: NativeString::from_bytes(
                            source.as_os_str().as_encoded_bytes().to_vec(),
                        )
                        .unwrap(),
                        dest: NativeString::Text((*id).to_owned()),
                        mode: MODE_COPY_RW.to_owned(),
                    }
                })
                .collect(),
        }
    }

    /// The names a vendor-state directory holds.
    fn entries(path: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The check before each credential, apart from the one before the state
    /// directories: an abandoned worker with no state directory to make
    /// refuses before it touches the next source, so even a missing one
    /// refuses as abandoned rather than as missing; and a worker abandoned
    /// after its first credential stages no second one, the refusal listing
    /// exactly the first.
    #[test]
    fn an_abandoned_worker_opens_no_further_source() {
        let (_dir, path, handle) = directory();
        let vendor = handle.mkdir_at(&Name::new(b"vs").unwrap(), 0o700).unwrap();
        let missing = copies(&path, &["gone"]);
        std::fs::remove_file(path.join("gone")).unwrap();
        let refused = stage_reporting(&missing, vendor.as_fd(), &[], &|_| {}, &|| true)
            .expect_err("an abandoned worker stops");
        assert_eq!(refused.error.code, ErrorCode::CredentialUnavailable);
        assert!(
            refused.error.message.contains("abandoned"),
            "{}",
            refused.error.message
        );

        let launch = copies(&path, &["a", "b"]);
        let abandoned = AtomicBool::new(false);
        let refused = stage_reporting(
            &launch,
            vendor.as_fd(),
            &[],
            &|_| abandoned.store(true, Ordering::SeqCst),
            &|| abandoned.load(Ordering::SeqCst),
        )
        .expect_err("abandoned after the first credential");
        assert!(refused.error.message.contains("abandoned"));
        let staged: Vec<&str> = refused
            .staged
            .iter()
            .map(|credential| credential.record.id.as_str())
            .collect();
        assert_eq!(staged, ["a"]);
        assert_eq!(entries(&path.join("vs")), ["a"]);
    }

    /// The check once a source is open: opening a source on a hung
    /// filesystem can outlast the deadline, so a worker abandoned while it
    /// opened one creates no target for it. Here the first question (before
    /// the credential) says "go on" and every later one says "abandoned".
    #[test]
    fn a_worker_abandoned_while_opening_a_source_creates_no_target() {
        let (_dir, path, handle) = directory();
        let vendor = handle.mkdir_at(&Name::new(b"vs").unwrap(), 0o700).unwrap();
        let launch = copies(&path, &["a"]);
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let refused = stage_reporting(&launch, vendor.as_fd(), &[], &|_| {}, &|| {
            asked.fetch_add(1, Ordering::SeqCst) > 0
        })
        .expect_err("abandoned once the source was open");
        assert!(refused.error.message.contains("abandoned"));
        assert!(refused.staged.is_empty());
        assert_eq!(
            asked.load(Ordering::SeqCst),
            2,
            "asked before and after the open"
        );
        assert!(entries(&path.join("vs")).is_empty());
    }

    /// What `stage_within`'s refusal lists is what was reported before it
    /// gave up: a report after `abandon` is not recorded, however late the
    /// worker makes it.
    #[test]
    fn progress_records_nothing_after_it_is_abandoned() {
        let (_dir, path, handle) = directory();
        let vendor = handle.mkdir_at(&Name::new(b"vs").unwrap(), 0o700).unwrap();
        let staged = stage(&copies(&path, &["a", "b"]), vendor.as_fd(), &[]).unwrap();
        let progress = Progress::default();
        assert!(!progress.abandoned());
        progress.report(&staged[0]);
        let ids = |list: Vec<(CredentialRecord, SourceIdentity)>| {
            list.into_iter()
                .map(|(record, _)| record.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(progress.abandon()), ["a"]);
        assert!(progress.abandoned());
        progress.report(&staged[1]);
        assert_eq!(ids(progress.abandon()), ["a"], "the late report is dropped");
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
        assert!(matches!(result, Err(Abandoned::Deadline)), "{result:?}");
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
        assert!(matches!(result, Err(Abandoned::Deadline)), "{result:?}");
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
        assert!(matches!(
            within(
                &until(Instant::now() + std::time::Duration::from_secs(5)),
                || 7
            ),
            Ok(7)
        ));
    }

    /// A worker that ends without a result is not a deadline: reporting it
    /// as "did not finish within the preparation budget" with `retry` would
    /// misstate both the cause and the remedy.
    #[test]
    fn a_worker_that_dies_is_lost_not_late() {
        let result = within(
            &until(Instant::now() + std::time::Duration::from_secs(30)),
            || -> u8 { panic!("the staging worker fails") },
        );
        assert!(matches!(result, Err(Abandoned::Lost)), "{result:?}");
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
                    vault: None,
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
