//! The safety rules of state paths (§6.2): private directories and files
//! this operator owns under ancestors nobody else can replace, read with a
//! size cap and never through a link.

use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use super::{AttemptDir, accounts, anchored, unsafe_path, write_failed};
use crate::records::JailError;

/// Mode for every file this tool writes under the state root (§6.2).
pub const FILE_MODE: u32 = 0o600;
/// Mode for every directory this tool creates under the state root (§6.2).
pub const DIRECTORY_MODE: u32 = 0o700;

/// Creates `path` with mode 0700 when absent, then checks it (§6.2).
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when creation fails and
/// [`ErrorCode::UnsafeStatePath`] when the existing directory is a symlink, is
/// not owned by this user, or is group- or world-accessible.
pub fn create_private_dir(path: &Path) -> Result<(), JailError> {
    match std::fs::create_dir(path) {
        Ok(()) => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|error| write_failed(path, &error))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A missing parent: create the chain, then retry this level.
            if let Some(parent) = path.parent() {
                create_private_dir(parent)?;
            }
            std::fs::create_dir(path).map_err(|error| write_failed(path, &error))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|error| write_failed(path, &error))?;
        }
        Err(error) => return Err(write_failed(path, &error)),
    }
    check_state_dir(path)
}

/// Whether an object with this mode, owner and group can be written by an
/// account other than its owner. The sticky bit is the caller's concern.
///
/// World write always counts. Group write counts unless the group is the
/// owner's private group: stock Debian and Ubuntu give every account a group
/// of its own and a umask of 002, so an operator's own directories are
/// group-writable by nobody else. The jail accepts that, as Debian's OpenSSH
/// does, only when the group is the owner's primary group, lists no member
/// but the owner, and is no other account's primary group. An account the
/// system's user database does not enumerate cannot be seen, which is the
/// same limit OpenSSH accepts.
#[must_use]
pub fn writable_by_others(mode: u32, uid: u32, gid: u32) -> bool {
    if mode & 0o002 != 0 {
        return true;
    }
    if mode & 0o020 == 0 {
        return false;
    }
    !accounts::group_is_private_to(uid, gid)
}

/// Checks that `path` is a private directory this operator owns (§6.2).
///
/// Rejects a symlinked state root, foreign ownership and a mode that lets
/// anyone else read or write it. Every ancestor is checked too: §6.2 rejects
/// "unsafe parent replacement", and a private directory under a symlinked or
/// world-writable parent is not private.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] on any of those conditions.
pub fn check_state_dir(path: &Path) -> Result<(), JailError> {
    // The ancestor walk runs on the resolved path. `/var`, `/tmp` and `/etc`
    // are symlinks on macOS, so refusing a symlinked ancestor outright would
    // refuse every ordinary state root there; what "unsafe parent replacement"
    // really means is an ancestor that someone else can write.
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    check_state_ancestors(&resolved)?;
    check_one_dir(path)
}

/// Checks every ancestor of an already-resolved `path` (§6.2).
///
/// An ancestor may legitimately be shared (`/`, `/home`, `/tmp`), so the rule
/// is about who can replace an entry in it, not about who owns it: a directory
/// writable by others without the sticky bit lets anyone swap the next
/// component for their own, which is the "unsafe parent replacement" §6.2
/// names. `/tmp` passes because it is sticky.
///
/// The caller resolves the path first, so this walks real directories.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when an ancestor is not a directory
/// or is writable by anyone other than its owner without the sticky bit (a
/// group-writable ancestor whose group is its owner's private group is not;
/// see [`writable_by_others`]).
pub fn check_state_ancestors(path: &Path) -> Result<(), JailError> {
    let mut ancestors: Vec<&Path> = path.ancestors().skip(1).collect();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|error| unsafe_path(ancestor, format!("cannot be inspected: {error}")))?;
        if !metadata.is_dir() {
            return Err(unsafe_path(ancestor, "is not a directory"));
        }
        let mode = mode_of(&metadata);
        // `/tmp` is group- and world-writable but sticky, which is what makes
        // it safe against replacement of entries this operator owns.
        let (owner, group) = {
            use std::os::unix::fs::MetadataExt as _;
            (metadata.uid(), metadata.gid())
        };
        if writable_by_others(mode, owner, group) && mode & 0o1000 == 0 {
            return Err(unsafe_path(
                ancestor,
                format!(
                    "has mode {mode:04o}: an ancestor writable by others without the sticky bit \
                     permits parent replacement"
                ),
            ));
        }
    }
    Ok(())
}

fn check_one_dir(path: &Path) -> Result<(), JailError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| unsafe_path(path, format!("cannot be inspected: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(unsafe_path(path, "a state directory may not be a symlink"));
    }
    if !metadata.is_dir() {
        return Err(unsafe_path(path, "is not a directory"));
    }
    check_ownership(
        path,
        owner_of(&metadata),
        mode_of(&metadata),
        DIRECTORY_MODE,
    )
}

/// Checks that a state file is a private regular file this operator owns.
///
/// Used on descriptors this tool reopens rather than creates: `jail.lock` and a
/// pre-existing `trace.ndjson` are as much state as the receipt is.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when the file is a symlink, is not a
/// regular file, is foreign-owned or is readable by anyone else.
pub fn check_state_file(path: &Path) -> Result<(), JailError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(unsafe_path(path, format!("cannot be inspected: {error}"))),
    };
    if metadata.file_type().is_symlink() {
        return Err(unsafe_path(path, "a state file may not be a symlink"));
    }
    if !metadata.is_file() {
        return Err(unsafe_path(path, "is not a regular file"));
    }
    check_ownership(path, owner_of(&metadata), mode_of(&metadata), FILE_MODE)
}

fn owner_of(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    metadata.uid()
}

fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    metadata.mode() & 0o7777
}

/// The ownership and mode predicate of §6.2, over plain values.
///
/// Taking `uid` and `mode` rather than a `std::fs::Metadata` is what makes the
/// rule testable: a test cannot `chown` a file to another user, but it can ask
/// this function about one.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when `uid` is not this operator or
/// `mode` grants anything outside `expected`.
pub fn check_ownership(path: &Path, uid: u32, mode: u32, expected: u32) -> Result<(), JailError> {
    let effective = crate::sys::effective_uid();
    if uid != effective {
        return Err(unsafe_path(
            path,
            format!("is owned by uid {uid} rather than this operator ({effective})"),
        ));
    }
    let permissions = mode & 0o777;
    if permissions & !expected != 0 {
        return Err(unsafe_path(
            path,
            format!("has mode {permissions:04o}; {expected:04o} or stricter is required"),
        ));
    }
    Ok(())
}

/// Reads a file that must be a private regular file, with a size cap (§7, H3).
///
/// The project `ukai.toml` is child-controlled: it can be a fifo that never
/// ends, a symlink to `/dev/zero`, or larger than memory. This opens with
/// `O_NOFOLLOW | O_NONBLOCK`, checks with `fstat` that the descriptor really is
/// a regular file, and reads at most `cap` bytes.
///
/// `Ok(None)` means the file does not exist, which is the only condition that
/// is not an error: every other failure is the caller's to report.
///
/// # Errors
/// Returns `Err(io::Error)` for a symlink, a non-regular file, an oversized
/// file or any read failure.
pub fn read_capped(path: &Path, cap: u64) -> Result<Option<Vec<u8>>, std::io::Error> {
    read_capped_checked(path, cap, |_| Ok(()))
}

/// [`read_capped`], with `check` judging the open descriptor's metadata
/// before a byte is read, so an identity rule cannot be raced by a swap of
/// the path.
///
/// # Errors
/// As [`read_capped`], and whatever `check` returns.
pub fn read_capped_checked(
    path: &Path,
    cap: u64,
    check: impl FnOnce(&std::fs::Metadata) -> std::io::Result<()>,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if metadata.len() > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("is {} bytes; the maximum is {cap}", metadata.len()),
        ));
    }
    check(&metadata)?;
    // `O_NONBLOCK` keeps the open from hanging on a fifo; the size check above
    // bounds a regular file, and `take` bounds anything that grows under us.
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file.take(cap + 1), &mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("grew past the {cap} byte maximum while being read"),
        ));
    }
    Ok(Some(bytes))
}

/// Opens this attempt's directory as the anchor for vendor-state work.
///
/// The attempt directory is operator state (§6.2): it must be a directory this
/// operator owns, mode 0700 or stricter, and not a symlink.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when it is not.
pub fn open_attempt_dir(attempt_dir: &AttemptDir) -> Result<anchored::Dir, JailError> {
    let root = attempt_dir.root();
    let dir = anchored::Dir::open_trusted(root)
        .map_err(|error| unsafe_path(root, format!("cannot be opened: {error}")))?;
    let stat = dir
        .stat()
        .map_err(|error| unsafe_path(root, format!("cannot be inspected: {error}")))?;
    check_ownership(root, stat.uid, stat.mode, DIRECTORY_MODE)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn world_write_always_counts_and_no_group_write_never_does() {
        assert!(writable_by_others(0o777, 0, 0));
        assert!(writable_by_others(0o702, 1000, 1000));
        assert!(!writable_by_others(0o755, 1000, 1000));
        assert!(!writable_by_others(0o700, 1000, 1000));
    }

    /// The stock Ubuntu home: a state root beneath a directory that is
    /// group-writable by the operator's own private group. Accepted exactly
    /// when the host's account database says the group is private (true for
    /// the reference host's accounts; false for macOS's shared `staff`).
    #[test]
    fn a_group_writable_ancestor_is_refused_unless_its_group_is_private() {
        use std::os::unix::fs::MetadataExt as _;
        let root = tempfile::tempdir().unwrap();
        let shared = root.path().join("dotlocal");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775)).unwrap();
        let state_root = shared.join("state");
        std::fs::create_dir(&state_root).unwrap();
        let metadata = std::fs::metadata(&shared).unwrap();
        let private = accounts::group_is_private_to(metadata.uid(), metadata.gid());
        let checked = check_state_ancestors(&state_root);
        assert_eq!(
            checked.is_ok(),
            private,
            "gid {} private: {private}; check: {checked:?}",
            metadata.gid()
        );
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            check_state_ancestors(&state_root).is_err(),
            "world write without the sticky bit is always refused"
        );
    }

    #[test]
    fn group_write_is_private_only_for_the_owners_own_group() {
        use accounts::{Facts, private};
        let name: &[u8] = b"ubuntu";
        let own = Facts {
            owner: Some((name, 1000)),
            members: Some(Vec::new()),
            another_primary: false,
        };
        assert!(private(1000, &own), "Ubuntu's user private group");
        let listed_self = Facts {
            members: Some(vec![b"ubuntu".to_vec()]),
            ..own
        };
        assert!(private(1000, &listed_self), "the owner listed as a member");
        let own = Facts {
            owner: Some((name, 1000)),
            members: Some(Vec::new()),
            another_primary: false,
        };
        assert!(!private(1001, &own), "not the owner's primary group");
        let shared = Facts {
            owner: Some((name, 1000)),
            members: Some(vec![b"ubuntu".to_vec(), b"someone".to_vec()]),
            another_primary: false,
        };
        assert!(!private(1000, &shared), "another listed member");
        let primary_elsewhere = Facts {
            owner: Some((name, 1000)),
            members: Some(Vec::new()),
            another_primary: true,
        };
        assert!(
            !private(1000, &primary_elsewhere),
            "another account's primary group"
        );
        let unknown_owner = Facts {
            owner: None,
            members: Some(Vec::new()),
            another_primary: false,
        };
        assert!(!private(1000, &unknown_owner));
        let unknown_group = Facts {
            owner: Some((name, 1000)),
            members: None,
            another_primary: false,
        };
        assert!(!private(1000, &unknown_group));
    }
}
