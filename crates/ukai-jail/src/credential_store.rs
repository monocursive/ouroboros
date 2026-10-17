//! J12: `ukai-jail credential set ID` and `credential rm ID`
//! (jail-launch-and-summary.md §3.5, §7 decision 6).
//!
//! Operator verbs that write and remove the files a launch profile's
//! `@config/credentials/ID` sources name, so an operator stores a vendor's
//! long-lived token once and every run vaults it. No agent is named here
//! (I02); the bundled launch profiles say which token each one takes.
//!
//! - The value is read from stdin only: never from argv, never echoed. One
//!   trailing LF is stripped; what remains must be 1 to
//!   [`crate::vault::VALUE_MAX`] printable ASCII bytes, the vault's own rule.
//!   A value with a line break is refused naming that cause, because a token
//!   copied from a wrapped terminal line arrives that way and, cut at the
//!   break, fails only when used (spike record 2026-10-16). It is never
//!   truncated.
//! - The file is created through a no-follow walk: every directory from `/`
//!   to the config directory owned by root or this operator and not
//!   writable by others without the sticky bit, `credentials/` created mode
//!   0700 (an existing one must be this operator's and closed to group and
//!   other writes), the file mode 0600 with `O_EXCL`. `--force` replaces an
//!   existing regular file of this operator's by a checked rename of a new
//!   private file; a symlink, a directory or anything else refuses.
//! - `rm` unlinks the same name after the same walk; a live vault lease
//!   whose source disappears is revoked by the vault's own poll.
//!
//! No message ever carries the value or a byte of it.

use std::ffi::OsStr;
use std::io::{Read, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use crate::state::anchored::{self, Dir, Kind, Name};

/// The directory beneath the config directory that holds the files.
pub const DIRECTORY: &str = "credentials";

/// Why a value read from stdin cannot be stored. The messages name the rule
/// broken, never the value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValueRefusal {
    /// Nothing but at most one line ending was read.
    Empty,
    /// More than [`crate::vault::VALUE_MAX`] bytes.
    TooLong,
    /// A line break inside the value.
    LineBreak,
    /// A carriage return (a CRLF line ending, or one inside the value).
    CarriageReturn,
    /// Another byte that is not printable ASCII.
    NotPrintable,
}

impl std::fmt::Display for ValueRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ValueRefusal::Empty => "the value is empty",
            ValueRefusal::TooLong => "the value is longer than 8192 bytes",
            ValueRefusal::LineBreak => {
                "the value contains a line break; a token copied from a wrapped terminal line \
                 must be rejoined into one line before it is pasted (nothing was stored)"
            }
            ValueRefusal::CarriageReturn => {
                "the value contains a carriage return (a CRLF line ending, or one inside the \
                 value); store it with a plain LF ending or none (nothing was stored)"
            }
            ValueRefusal::NotPrintable => {
                "the value contains a byte that is not printable ASCII (a tab, a control \
                 character or non-ASCII text); nothing was stored"
            }
        })
    }
}

/// Reads one value: everything until end of input, at most
/// [`crate::vault::VALUE_MAX`] bytes plus one line ending, with exactly one
/// trailing LF stripped.
///
/// # Errors
/// The [`ValueRefusal`] of a value the vault would not accept, or the read
/// error.
pub fn read_value(
    input: &mut impl Read,
) -> std::io::Result<Result<zeroize::Zeroizing<Vec<u8>>, ValueRefusal>> {
    let max = crate::vault::VALUE_MAX;
    let mut value = zeroize::Zeroizing::new(Vec::with_capacity(max + 2));
    input.take(max as u64 + 2).read_to_end(&mut value)?;
    if value.last() == Some(&b'\n') {
        value.pop();
    }
    Ok(check_value(&value).map(|()| value))
}

/// The vault's rule for a value, with the cause of a refusal named.
///
/// # Errors
/// Which part of the rule `value` breaks.
pub fn check_value(value: &[u8]) -> Result<(), ValueRefusal> {
    if value.is_empty() {
        return Err(ValueRefusal::Empty);
    }
    if value.len() > crate::vault::VALUE_MAX {
        return Err(ValueRefusal::TooLong);
    }
    if value.contains(&b'\n') {
        return Err(ValueRefusal::LineBreak);
    }
    if value.contains(&b'\r') {
        return Err(ValueRefusal::CarriageReturn);
    }
    if !crate::vault::valid_value(value) {
        return Err(ValueRefusal::NotPrintable);
    }
    Ok(())
}

/// The path `ID` is stored at.
#[must_use]
pub fn path_of(config_dir: &Path, id: &str) -> PathBuf {
    config_dir.join(DIRECTORY).join(id)
}

fn refuse(message: impl Into<String>) -> String {
    message.into()
}

/// Checks `id` against the credential-id grammar.
///
/// # Errors
/// Why it is not an id.
pub fn check_id(id: &str) -> Result<(), String> {
    if crate::launch_profile::valid_credential_id(id) {
        Ok(())
    } else {
        Err(format!(
            "`{}` is not a credential id ([A-Za-z0-9][A-Za-z0-9_.-]{{0,63}})",
            crate::records::escape_control(id)
        ))
    }
}

/// A directory on the walk: root or this operator, and not writable by
/// others without the sticky bit.
fn check_walked(stat: &anchored::Stat, path: &Path) -> Result<(), String> {
    let euid = crate::state::effective_uid();
    if stat.uid != 0 && stat.uid != euid {
        return Err(refuse(format!(
            "{} is owned by uid {}, neither root nor this operator",
            path.display(),
            stat.uid
        )));
    }
    if crate::state::writable_by_others(stat.mode, stat.uid, stat.gid) && stat.mode & 0o1000 == 0 {
        return Err(refuse(format!(
            "{} has mode {:04o}: writable by others without the sticky bit",
            path.display(),
            stat.mode
        )));
    }
    Ok(())
}

/// Opens the credentials directory beneath `config_dir` by a no-follow walk,
/// creating it (and a missing config directory, mode 0700) when `create`.
/// `Ok(None)` when it does not exist and `create` is false.
fn open_directory(config_dir: &Path, create: bool) -> Result<Option<(Dir, PathBuf)>, String> {
    if !config_dir.is_absolute() {
        return Err(refuse(format!(
            "the config directory {} is not absolute",
            config_dir.display()
        )));
    }
    // The config directory's own spelling is the operator's (a symlinked
    // `~/.config` is their choice), as the launch-profile loader treats it:
    // its deepest existing ancestor is resolved, and from `/` down
    // everything is then walked again with no symlink followed.
    let mut existing = config_dir.to_path_buf();
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    while existing.symlink_metadata().is_err() {
        let Some(name) = existing.file_name().map(OsStr::to_os_string) else {
            break;
        };
        missing.push(name);
        if !existing.pop() {
            break;
        }
    }
    let resolved = std::fs::canonicalize(&existing).map_err(|error| {
        refuse(format!(
            "{} cannot be resolved: {error}",
            existing.display()
        ))
    })?;
    let components = anchored::split_absolute(resolved.as_os_str().as_bytes())
        .map_err(|error| refuse(error.to_string()))?;
    let mut current = Dir::open_root_for_walk()
        .map_err(|error| refuse(format!("`/` cannot be opened: {error}")))?;
    let mut walked = PathBuf::from("/");
    check_walked(&current.stat().map_err(|e| refuse(e.to_string()))?, &walked)?;
    for component in &components {
        walked.push(OsStr::from_bytes(component.as_bytes()));
        let stat = current
            .stat_at(component)
            .map_err(|error| refuse(format!("{}: {error}", walked.display())))?;
        if stat.kind != Kind::Directory {
            return Err(refuse(format!(
                "{} is {}, not a directory",
                walked.display(),
                stat.kind.describe()
            )));
        }
        check_walked(&stat, &walked)?;
        current = current
            .open_walk_at(component, Some(&stat))
            .map_err(|error| refuse(format!("{}: {error}", walked.display())))?;
    }
    let mut remaining: Vec<std::ffi::OsString> = missing.into_iter().rev().collect();
    remaining.push(DIRECTORY.into());
    for (index, name) in remaining.iter().enumerate() {
        walked.push(name);
        let component = Name::new(name.as_bytes()).map_err(|error| refuse(error.to_string()))?;
        let last = index + 1 == remaining.len();
        current = match current.stat_at(&component) {
            Ok(stat) => {
                if stat.kind != Kind::Directory {
                    return Err(refuse(format!(
                        "{} is {}, not a directory",
                        walked.display(),
                        stat.kind.describe()
                    )));
                }
                check_walked(&stat, &walked)?;
                if last && (stat.uid != crate::state::effective_uid() || stat.mode & 0o022 != 0) {
                    return Err(refuse(format!(
                        "{} must be this operator's and closed to group and other writes \
                         (mode {:04o}, uid {})",
                        walked.display(),
                        stat.mode,
                        stat.uid
                    )));
                }
                current
                    .open_dir_at(&component, Some(&stat))
                    .map_err(|error| refuse(format!("{}: {error}", walked.display())))?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !create {
                    return Ok(None);
                }
                let created = current
                    .mkdir_at(&component, 0o700)
                    .map_err(|error| refuse(format!("{}: {error}", walked.display())))?;
                // Best effort: a walk handle (`O_PATH` on Linux) cannot be
                // synced, and the new directory is synced below anyway.
                let _ = current.sync();
                created
            }
            Err(error) => return Err(refuse(format!("{}: {error}", walked.display()))),
        };
    }
    Ok(Some((current, walked)))
}

/// Stores `value` as `<config_dir>/credentials/<id>`, mode 0600: created
/// with `O_EXCL`, or with `force` replacing an existing regular file of this
/// operator's by a checked rename. Returns the path written.
///
/// # Errors
/// Why nothing was stored; the message never carries the value.
pub fn set(config_dir: &Path, id: &str, value: &[u8], force: bool) -> Result<PathBuf, String> {
    check_id(id)?;
    check_value(value).map_err(|refusal| refusal.to_string())?;
    let (directory, path) = open_directory(config_dir, true)?
        .ok_or_else(|| refuse("the credentials directory could not be created"))?;
    let path = path.join(id);
    let name = Name::new(id.as_bytes()).map_err(|error| refuse(error.to_string()))?;
    let existing = match directory.stat_at(&name) {
        Ok(stat) => Some(stat),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(refuse(format!("{}: {error}", path.display()))),
    };
    let write = |file: &mut std::fs::File| -> std::io::Result<()> {
        file.write_all(value)?;
        file.sync_all()
    };
    let Some(existing) = existing else {
        let mut file = directory
            .create_file_at(&name, 0o600)
            .map_err(|error| refuse(format!("{}: {error}", path.display())))?;
        if let Err(error) = write(&mut file) {
            drop(file);
            let _ = directory.unlink_at(&name);
            return Err(refuse(format!("{}: {error}", path.display())));
        }
        directory
            .sync()
            .map_err(|error| refuse(format!("{}: {error}", path.display())))?;
        return Ok(path);
    };
    if !force {
        return Err(refuse(format!(
            "{} exists already; pass --force to replace it",
            path.display()
        )));
    }
    check_replaceable(&existing, &path)?;
    let temporary = format!(".{id}.{}.tmp", uuid::Uuid::new_v4().simple());
    let temporary = Name::new(temporary.as_bytes()).map_err(|error| refuse(error.to_string()))?;
    let mut file = directory
        .create_file_at(&temporary, 0o600)
        .map_err(|error| refuse(format!("{}: {error}", path.display())))?;
    let replaced = write(&mut file)
        .map_err(|error| refuse(format!("{}: {error}", path.display())))
        .and_then(|()| {
            // Checked: the name still holds the file judged above.
            let now = directory
                .stat_at(&name)
                .map_err(|error| refuse(format!("{}: {error}", path.display())))?;
            if now.identity() != existing.identity() {
                return Err(refuse(format!(
                    "{} was replaced while the new value was written",
                    path.display()
                )));
            }
            check_replaceable(&now, &path)?;
            directory
                .rename_at(&temporary, &directory, &name)
                .map_err(|error| refuse(format!("{}: {error}", path.display())))
        });
    drop(file);
    if let Err(error) = replaced {
        let _ = directory.unlink_at(&temporary);
        return Err(error);
    }
    directory
        .sync()
        .map_err(|error| refuse(format!("{}: {error}", path.display())))?;
    Ok(path)
}

/// An existing entry `--force` may replace, or `rm` remove: a regular file
/// this operator owns, with one link.
fn check_replaceable(stat: &anchored::Stat, path: &Path) -> Result<(), String> {
    if stat.kind != Kind::Regular {
        return Err(refuse(format!(
            "{} is {}, not a credential file; remove it by hand",
            path.display(),
            stat.kind.describe()
        )));
    }
    if stat.uid != crate::state::effective_uid() {
        return Err(refuse(format!(
            "{} is owned by uid {}, not this operator",
            path.display(),
            stat.uid
        )));
    }
    if stat.nlink != 1 {
        return Err(refuse(format!(
            "{} has {} hard links; another name for it could lie anywhere",
            path.display(),
            stat.nlink
        )));
    }
    Ok(())
}

/// Removes `<config_dir>/credentials/<id>`. Returns the path removed.
///
/// # Errors
/// Why nothing was removed: no such credential, or an entry that is not a
/// credential file of this operator's.
pub fn remove(config_dir: &Path, id: &str) -> Result<PathBuf, String> {
    check_id(id)?;
    let path = path_of(config_dir, id);
    let Some((directory, walked)) = open_directory(config_dir, false)? else {
        return Err(refuse(format!(
            "there is no credential `{id}` ({})",
            path.display()
        )));
    };
    let path = walked.join(id);
    let name = Name::new(id.as_bytes()).map_err(|error| refuse(error.to_string()))?;
    let stat = match directory.stat_at(&name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(refuse(format!(
                "there is no credential `{id}` ({})",
                path.display()
            )));
        }
        Err(error) => return Err(refuse(format!("{}: {error}", path.display()))),
    };
    check_replaceable(&stat, &path)?;
    directory
        .unlink_at(&name)
        .map_err(|error| refuse(format!("{}: {error}", path.display())))?;
    directory
        .sync()
        .map_err(|error| refuse(format!("{}: {error}", path.display())))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    /// A synthetic `fstat` result: what a second local user's object looks
    /// like, which a single-uid test cannot create.
    fn synthetic(kind: Kind, uid: u32, mode: u32) -> anchored::Stat {
        anchored::Stat {
            dev: 1,
            ino: 2,
            kind,
            mode,
            uid,
            gid: u32::MAX - 1,
            nlink: 1,
            size: 0,
            mtime: (0, 0),
            ctime: (0, 0),
            mount_root: Some(false),
        }
    }

    /// The owner rules, which need a second local user end to end: a
    /// directory on the walk owned by someone else, and an existing entry
    /// someone else owns, refuse.
    #[test]
    fn foreign_owners_refuse_on_the_walk_and_the_replaced_file() {
        let me = crate::state::effective_uid();
        let other = if me == 4242 { 4243 } else { 4242 };
        let path = Path::new("/x");
        assert!(check_walked(&synthetic(Kind::Directory, other, 0o755), path).is_err());
        assert!(check_walked(&synthetic(Kind::Directory, me, 0o755), path).is_ok());
        assert!(check_walked(&synthetic(Kind::Directory, 0, 0o755), path).is_ok());
        assert!(check_replaceable(&synthetic(Kind::Regular, other, 0o600), path).is_err());
        assert!(check_replaceable(&synthetic(Kind::Regular, me, 0o600), path).is_ok());
    }

    fn config() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, root.join("config"))
    }

    #[test]
    fn one_trailing_lf_is_stripped_and_a_line_break_is_named() {
        let read = |bytes: &[u8]| read_value(&mut &bytes[..]).unwrap();
        assert_eq!(read(b"sk-abc\n").unwrap().as_slice(), b"sk-abc");
        assert_eq!(read(b"sk-abc").unwrap().as_slice(), b"sk-abc");
        assert_eq!(read(b"sk-abc\n\n"), Err(ValueRefusal::LineBreak));
        assert_eq!(read(b"sk-a\nbc\n"), Err(ValueRefusal::LineBreak));
        assert_eq!(read(b"sk-abc\r\n"), Err(ValueRefusal::CarriageReturn));
        assert_eq!(read(b"sk\tabc"), Err(ValueRefusal::NotPrintable));
        assert_eq!(read(b"\n"), Err(ValueRefusal::Empty));
        assert_eq!(read(b""), Err(ValueRefusal::Empty));
        let long = vec![b'a'; crate::vault::VALUE_MAX + 1];
        assert_eq!(read(&long), Err(ValueRefusal::TooLong));
        let max = vec![b'a'; crate::vault::VALUE_MAX];
        assert!(read(&max).is_ok());
        // The cause, never the value.
        let message = ValueRefusal::LineBreak.to_string();
        assert!(message.contains("wrapped terminal line"), "{message}");
    }

    #[test]
    fn set_creates_private_modes_and_force_replaces_by_rename() {
        let (_dir, config) = config();
        let path = set(&config, "api", b"first", false).unwrap();
        assert_eq!(path, config.join("credentials/api"));
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o7777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&config.join("credentials")), 0o700);
        assert_eq!(mode(&config), 0o700);
        let error = set(&config, "api", b"second", false).unwrap_err();
        assert!(error.contains("--force"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        let before = std::fs::metadata(&path).unwrap().ino();
        set(&config, "api", b"second", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert_ne!(std::fs::metadata(&path).unwrap().ino(), before);
        assert_eq!(mode(&path), 0o600);
        // No temporary file is left behind.
        let names: Vec<_> = std::fs::read_dir(config.join("credentials"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["api"]);
        assert!(set(&config, "../x", b"v", false).is_err());
        assert!(
            set(&config, "bad", b"a\nb", false)
                .unwrap_err()
                .contains("line break")
        );
    }

    #[test]
    fn symlinks_and_shared_writable_directories_refuse() {
        let (_dir, config) = config();
        std::fs::create_dir_all(config.join(DIRECTORY)).unwrap();
        std::fs::set_permissions(
            config.join(DIRECTORY),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let target = config.parent().unwrap().join("elsewhere");
        std::fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, config.join(DIRECTORY).join("api")).unwrap();
        assert!(
            set(&config, "api", b"v", false)
                .unwrap_err()
                .contains("exists")
        );
        assert!(
            set(&config, "api", b"v", true)
                .unwrap_err()
                .contains("a symlink")
        );
        assert!(remove(&config, "api").unwrap_err().contains("a symlink"));
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        std::fs::remove_file(config.join(DIRECTORY).join("api")).unwrap();

        std::fs::set_permissions(
            config.join(DIRECTORY),
            std::fs::Permissions::from_mode(0o770),
        )
        .unwrap();
        assert!(set(&config, "api", b"v", false).is_err());
        std::fs::set_permissions(
            config.join(DIRECTORY),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        // A symlinked credentials directory is never followed.
        std::fs::remove_dir(config.join(DIRECTORY)).unwrap();
        let other = config.parent().unwrap().join("other");
        std::fs::create_dir(&other).unwrap();
        std::os::unix::fs::symlink(&other, config.join(DIRECTORY)).unwrap();
        assert!(set(&config, "api", b"v", false).is_err());
        assert!(!other.join("api").exists());
    }

    /// J12 adversarial review: a credential file with a second name refuses
    /// `--force` and `rm` (the other name could lie anywhere). Kills:
    /// `check_replaceable` without its link count.
    #[test]
    fn review_a_hard_linked_credential_is_neither_replaced_nor_removed() {
        let (_dir, config) = config();
        let path = set(&config, "api", b"first", false).unwrap();
        let other = config.parent().unwrap().join("other-name");
        std::fs::hard_link(&path, &other).unwrap();
        assert!(
            set(&config, "api", b"second", true)
                .unwrap_err()
                .contains("hard links")
        );
        assert!(remove(&config, "api").unwrap_err().contains("hard links"));
        assert_eq!(std::fs::read(&other).unwrap(), b"first");
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
    }

    /// J12 adversarial review. Kills: the credentials directory's own
    /// owner and mode rule (a sticky world-writable directory passes the
    /// walk's writable-by-others rule; only that rule refuses it).
    #[test]
    fn review_a_sticky_shared_credentials_directory_refuses() {
        let (_dir, config) = config();
        std::fs::create_dir_all(config.join(DIRECTORY)).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            config.join(DIRECTORY),
            std::fs::Permissions::from_mode(0o1777),
        )
        .unwrap();
        assert!(set(&config, "api", b"v", false).is_err());
        assert!(!config.join(DIRECTORY).join("api").exists());
    }

    /// J12 adversarial review. Kills: the walk's writable-by-others rule
    /// above the credentials directory (masked for `credentials/` itself by
    /// its own mode rule).
    #[test]
    fn review_a_world_writable_config_directory_refuses() {
        let (_dir, config) = config();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(set(&config, "api", b"v", false).is_err());
        assert!(!config.join(DIRECTORY).join("api").exists());
    }

    /// J12 adversarial review. Kills: `check_id` reduced to "no slash".
    #[test]
    fn review_ids_outside_the_grammar_refuse() {
        for id in [".hidden", "a b", "-x", "x\ny", "", &"a".repeat(65)] {
            assert!(check_id(id).is_err(), "{id:?}");
        }
    }

    #[test]
    fn remove_unlinks_and_reports_absence() {
        let (_dir, config) = config();
        assert!(
            remove(&config, "api")
                .unwrap_err()
                .contains("no credential")
        );
        set(&config, "api", b"v", false).unwrap();
        remove(&config, "api").unwrap();
        assert!(!config.join("credentials/api").exists());
        assert!(
            remove(&config, "api")
                .unwrap_err()
                .contains("no credential")
        );
    }
}
