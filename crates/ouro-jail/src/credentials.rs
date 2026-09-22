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
//!   [`COPY_BUDGET`]; a larger input refuses before any byte of it is copied,
//!   and in every case before the target executes.
//! - `bind_ro` exposes the exact granted source file read-only. Staging holds
//!   a descriptor of that exact object (an `O_PATH` handle on Linux) and hands
//!   it to the platform, which binds it with `--ro-bind-fd`, so the object the
//!   checks examined is the object mounted. Its digest is recorded only when
//!   stable content can be established — the source lies on a read-only
//!   filesystem and did not change while it was hashed — and is otherwise
//!   null with a safe reason: the operator's live file can change during the
//!   attempt, and a digest of what it held at staging would claim more than
//!   was established.
//!
//! Nothing here recurses through a directory, follows a symlink or opens a
//! special file for I/O: a FIFO, a socket, a device, a symlink and a directory
//! all refuse, and on Linux they are refused after an `O_PATH` open that has
//! no open-time side effect on the object. Error messages name the logical
//! credential id, never a source path, because errors reach the receipt.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;

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

/// The bound source can change during the attempt: it is not on a read-only
/// filesystem, so no digest describes what the child will read.
pub const REASON_SOURCE_MUTABLE: &str = "bind_ro_source_mutable";
/// The bound source changed while it was being hashed.
pub const REASON_SOURCE_CHANGED: &str = "bind_ro_source_changed_while_hashed";
/// The bound source is larger than [`DIGEST_BUDGET`].
pub const REASON_TOO_LARGE: &str = "bind_ro_source_exceeds_digest_budget";

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
/// On success every declared credential is staged, in id order. On refusal
/// the error comes with the records of the credentials staged before the
/// failure, which §12 lets the refused receipt report.
///
/// # Errors
/// [`ErrorCode::CredentialUnavailable`] for a missing, special, foreign,
/// shared-writable, oversized or changing source, and
/// [`ErrorCode::StateWriteFailed`] when vendor state cannot be written.
pub fn stage(
    launch: &LaunchSnapshot,
    vendor_state: BorrowedFd<'_>,
) -> Result<Vec<StagedCredential>, (JailError, Vec<CredentialRecord>)> {
    let vendor = vendor_state
        .try_clone_to_owned()
        .map(Dir::from_owned)
        .map_err(|error| (state_failure("*", "descriptor", &error), Vec::new()))?;

    let mut subdirs: Vec<&NativeString> = launch.state_subdirs.iter().collect();
    subdirs.sort();
    for subdir in subdirs {
        let components = anchored::split_relative(subdir.as_bytes()).map_err(|error| {
            (
                JailError::new(
                    ErrorCode::InvalidConfig,
                    ErrorStage::Preparing,
                    Remediation::Configuration,
                    format!("a state subdirectory is not a relative path: {error}"),
                )
                .with_key_path("launch.state_subdirs"),
                Vec::new(),
            )
        })?;
        ensure_directories(&vendor, &components).map_err(|error| {
            (
                state_failure("state_subdirs", "create directory", &error),
                Vec::new(),
            )
        })?;
    }

    let mut declarations: Vec<&CredentialDecl> = launch.credentials.iter().collect();
    declarations.sort_by(|left, right| left.id.cmp(&right.id));
    let mut staged: Vec<StagedCredential> = Vec::new();
    let mut copied: u64 = 0;
    for declaration in declarations {
        match stage_one(&vendor, declaration, &mut copied) {
            Ok(credential) => staged.push(credential),
            Err(error) => {
                let records = staged.iter().map(|item| item.record.clone()).collect();
                return Err((error, records));
            }
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

fn stage_one(
    vendor: &Dir,
    declaration: &CredentialDecl,
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

    let source = open_source(id, declaration.source.as_bytes())?;
    let identity = SourceIdentity {
        dev: source.stat.dev,
        ino: source.stat.ino,
        size: source.stat.size,
    };

    if mode == MODE_COPY_RW && source.stat.size > COPY_BUDGET.saturating_sub(*copied) {
        return Err(refusal(
            id,
            Remediation::Configuration,
            format!(
                "copying {} bytes would exceed the {} byte credential-copy budget per attempt",
                source.stat.size, COPY_BUDGET
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
            anchored::reopen_for_read(self.handle.as_fd())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Not O_PATH here: the handle was opened for reading and is used
            // directly, from its start, exactly once per staging.
            self.handle.try_clone().map(File::from)
        }
    }
}

/// Opens an absolute source path with a no-follow walk from `/` (§12).
///
/// Every directory on the way is opened relative to the previous one with
/// `O_NOFOLLOW`, checked to be the object `fstatat` described, and must be
/// owned by this operator or root and not writable by anyone else unless it
/// is sticky: a directory someone else can write lets them swap the next
/// component. The final component must be a regular file owned by this
/// operator or root with no group or other write bit.
fn open_source(id: &str, path: &[u8]) -> Result<Source, JailError> {
    let unusable = |message: String| refusal(id, Remediation::Configuration, message);
    let components = anchored::split_absolute(path)
        .map_err(|error| unusable(format!("the source is not an absolute path: {error}")))?;
    let Some((file_name, directories)) = components.split_last() else {
        return Err(unusable("the source names the filesystem root".to_owned()));
    };
    let mut current = Dir::open_root_for_walk()
        .map_err(|error| unusable(format!("the filesystem root cannot be opened: {error}")))?;
    check_directory(
        id,
        &current
            .stat()
            .map_err(|error| unusable(error.to_string()))?,
    )?;
    for component in directories {
        let stat = match current.stat_at(component) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(unusable("the source does not exist".to_owned()));
            }
            Err(error) => {
                return Err(unusable(format!(
                    "the source path cannot be inspected: {error}"
                )));
            }
        };
        if stat.kind != Kind::Directory {
            return Err(unusable(format!(
                "a component of the source path is {}, and a credential path is never followed \
                 through one",
                stat.kind.describe()
            )));
        }
        current = current
            .open_walk_at(component, Some(&stat))
            .map_err(|error| unusable(format!("the source path cannot be opened: {error}")))?;
        check_directory(id, &stat)?;
    }
    let stat = match current.stat_at(file_name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(unusable("the source does not exist".to_owned()));
        }
        Err(error) => return Err(unusable(format!("the source cannot be inspected: {error}"))),
    };
    check_file(id, &stat)?;
    let handle = open_final(&current, file_name, &stat)
        .map_err(|error| unusable(format!("the source cannot be opened: {error}")))?;
    let opened = anchored::fstat(handle.as_fd())
        .map_err(|error| unusable(format!("the source cannot be inspected: {error}")))?;
    if opened.identity() != stat.identity() {
        return Err(refusal(
            id,
            Remediation::Retry,
            "the source was replaced while it was being opened",
        ));
    }
    check_file(id, &opened)?;
    Ok(Source {
        handle,
        stat: opened,
    })
}

#[cfg(target_os = "linux")]
fn open_final(dir: &Dir, name: &Name, _stat: &Stat) -> std::io::Result<OwnedFd> {
    dir.open_path_at(name)
}

#[cfg(not(target_os = "linux"))]
fn open_final(dir: &Dir, name: &Name, stat: &Stat) -> std::io::Result<OwnedFd> {
    dir.open_read_at(name, Some(stat)).map(OwnedFd::from)
}

fn check_directory(id: &str, stat: &Stat) -> Result<(), JailError> {
    let euid = crate::state::effective_uid();
    if stat.uid != 0 && stat.uid != euid {
        return Err(refusal(
            id,
            Remediation::Configuration,
            format!(
                "a directory on the source path is owned by uid {}, neither root nor this \
                 operator ({euid})",
                stat.uid
            ),
        ));
    }
    if stat.mode & 0o022 != 0 && stat.mode & 0o1000 == 0 {
        return Err(refusal(
            id,
            Remediation::Configuration,
            format!(
                "a directory on the source path has mode {:04o}: writable by others without \
                 the sticky bit, so its entries can be replaced",
                stat.mode
            ),
        ));
    }
    Ok(())
}

fn check_file(id: &str, stat: &Stat) -> Result<(), JailError> {
    if stat.kind != Kind::Regular {
        return Err(refusal(
            id,
            Remediation::Configuration,
            format!(
                "the source is {}; only a regular file is staged, and a credential directory \
                 is never recursed",
                stat.kind.describe()
            ),
        ));
    }
    let euid = crate::state::effective_uid();
    if stat.uid != 0 && stat.uid != euid {
        return Err(refusal(
            id,
            Remediation::Configuration,
            format!(
                "the source is owned by uid {}, neither root nor this operator ({euid})",
                stat.uid
            ),
        ));
    }
    if stat.mode & 0o022 != 0 {
        return Err(refusal(
            id,
            Remediation::Configuration,
            format!(
                "the source has mode {:04o}; a credential others can write is refused",
                stat.mode
            ),
        ));
    }
    Ok(())
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
    if total != expected || !after.unchanged_since(&source.stat) {
        return Err(refusal(
            id,
            Remediation::Retry,
            "the source changed while it was being copied; a point-in-time copy was not \
             established",
        ));
    }
    Ok(hex(&hasher.finalize()))
}

/// The digest of a `bind_ro` source, when stable content can be established.
fn bind_digest(source: &Source) -> (Option<String>, Option<&'static str>) {
    match anchored::readonly_filesystem(source.handle.as_fd()) {
        Ok(true) => {}
        _ => return (None, Some(REASON_SOURCE_MUTABLE)),
    }
    if source.stat.size > DIGEST_BUDGET {
        return (None, Some(REASON_TOO_LARGE));
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
    let unchanged = anchored::fstat(limited.get_ref().as_fd())
        .is_ok_and(|after| after.unchanged_since(&source.stat));
    if total != source.stat.size || !unchanged {
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

    #[test]
    fn a_digest_is_the_prefixed_lowercase_hex_the_receipt_schema_requires() {
        let digest = hex(&Sha256::digest(b"abc"));
        assert_eq!(
            digest,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
