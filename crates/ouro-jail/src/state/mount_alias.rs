//! Child-writable grants viewed through another Linux mountpoint.
//!
//! A no-follow source walk sees the inode at an alias mountpoint, not the
//! grant's pathname ancestors. Mountinfo gives both mountpoints coordinates
//! in their underlying filesystem, including the root of a bind mount.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// Identities which a source's no-follow path walk must never cross.
/// Missing roots (such as a scratch directory not yet made) are harmless.
pub fn forbidden_identities(roots: &[PathBuf]) -> io::Result<Vec<(u64, u64)>> {
    let mut identities = Vec::new();
    let mut existing = Vec::new();
    for root in roots {
        match fs::canonicalize(root) {
            Ok(path) => {
                let stat = fs::metadata(&path)?;
                identities.push((stat.dev(), stat.ino()));
                existing.push((path, stat.dev()));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mounts = read_mountinfo()?;
        identities.extend(alias_identities(&existing, &mounts)?);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = existing;
    identities.sort_unstable();
    identities.dedup();
    Ok(identities)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct Mount {
    point: PathBuf,
    root: PathBuf,
    dev: u64,
    ino: u64,
}

#[cfg(target_os = "linux")]
fn read_mountinfo() -> io::Result<Vec<Mount>> {
    use std::io::Read as _;
    use std::os::unix::ffi::OsStringExt as _;
    let mut bytes = Vec::new();
    fs::File::open("/proc/self/mountinfo")?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mountinfo too large",
        ));
    }
    let mut mounts = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
        if fields.len() < 7 || !fields.iter().any(|field| *field == b"-") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed mountinfo",
            ));
        }
        let root = PathBuf::from(std::ffi::OsString::from_vec(unescape(fields[3])?));
        let point = PathBuf::from(std::ffi::OsString::from_vec(unescape(fields[4])?));
        if !root.is_absolute() || !point.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "relative mountinfo path",
            ));
        }
        // An overmounted entry may no longer be reachable. Only visible
        // mountpoints can carry a source path or a writable grant.
        if let Ok(stat) = fs::metadata(&point) {
            mounts.push(Mount {
                point,
                root,
                dev: stat.dev(),
                ino: stat.ino(),
            });
        }
    }
    Ok(mounts)
}

#[cfg(target_os = "linux")]
fn unescape(input: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut at = 0;
    while at < input.len() {
        if input[at] == b'\\' {
            if at + 3 >= input.len()
                || !input[at + 1..at + 4]
                    .iter()
                    .all(|b| (b'0'..=b'7').contains(b))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad mountinfo escape",
                ));
            }
            let value = u16::from(input[at + 1] - b'0') * 64
                + u16::from(input[at + 2] - b'0') * 8
                + u16::from(input[at + 3] - b'0');
            let value = u8::try_from(value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad mountinfo escape"))?;
            out.push(value);
            at += 4;
        } else {
            out.push(input[at]);
            at += 1;
        }
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn alias_identities(grants: &[(PathBuf, u64)], mounts: &[Mount]) -> io::Result<Vec<(u64, u64)>> {
    let mut writable = Vec::new();
    for (path, dev) in grants {
        let containing = mounts
            .iter()
            .filter(|mount| path.starts_with(&mount.point) && mount.dev == *dev)
            .max_by_key(|mount| mount.point.as_os_str().len())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "grant absent from mountinfo")
            })?;
        let relative = path
            .strip_prefix(&containing.point)
            .expect("prefix checked");
        writable.push((*dev, containing.root.join(relative)));
        // A recursive grant also exposes mounts below its root, potentially
        // on other devices. Their aliases are writable too.
        writable.extend(
            mounts
                .iter()
                .filter(|mount| mount.point.starts_with(path))
                .map(|mount| (mount.dev, mount.root.clone())),
        );
    }
    Ok(mounts
        .iter()
        .filter(|mount| {
            writable
                .iter()
                .any(|(dev, root)| mount.dev == *dev && mount.root.starts_with(root))
        })
        .map(|mount| (mount.dev, mount.ino))
        .collect())
}

/// Security 2026-09-27 (audit 4 B4): the first mount beneath any child root
/// that reaches `guarded` through bind-alias coordinates, if one exists.
///
/// The supervisor's isolation guards compare canonicalized paths, which
/// cannot see that a mount somewhere beneath a child-visible root is a bind
/// of the guarded directory (or of something containing it). This answers
/// exactly that question from mountinfo: a mount reaches the guarded tree
/// when it lives on the same device and its filesystem coordinates overlap
/// the guarded tree's own, and it is visible to the child when its mount
/// point is at or beneath a child root. `Ok(None)` when no such mount
/// exists; a `guarded` path that does not exist has no coordinates and no
/// aliases. Off Linux there are no bind aliases to find.
///
/// # Errors
/// Returns `Err(io::Error)` when mountinfo cannot be read or parsed.
pub fn alias_conflict(child_roots: &[PathBuf], guarded: &Path) -> io::Result<Option<PathBuf>> {
    find_alias(child_roots, guarded, false)
}

/// Whether a destination directory lies inside the guarded tree through a
/// mount alias. A destination containing that tree is not itself inside it.
pub fn alias_containment(destinations: &[PathBuf], guarded: &Path) -> io::Result<Option<PathBuf>> {
    find_alias(destinations, guarded, true)
}

fn find_alias(
    child_roots: &[PathBuf],
    guarded: &Path,
    contained: bool,
) -> io::Result<Option<PathBuf>> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (child_roots, guarded, contained);
        Ok(None)
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(canonical) = fs::canonicalize(guarded) else {
            return Ok(None);
        };
        let stat = fs::metadata(&canonical)?;
        let mounts = read_mountinfo()?;
        Ok(translated_conflict(
            child_roots,
            &canonical,
            stat.dev(),
            &mounts,
            contained,
        ))
    }
}

/// The Linux core of [`alias_conflict`], over a supplied mount table so
/// the coordinate math is unit-testable (audit 4 B4).
#[cfg(all(test, target_os = "linux"))]
fn conflict_in_mounts(
    child_roots: &[PathBuf],
    canonical: &Path,
    dev: u64,
    mounts: &[Mount],
) -> Option<PathBuf> {
    translated_conflict(child_roots, canonical, dev, mounts, false)
}

#[cfg(target_os = "linux")]
fn translated_conflict(
    child_roots: &[PathBuf],
    canonical: &Path,
    dev: u64,
    mounts: &[Mount],
    contained: bool,
) -> Option<PathBuf> {
    // The guarded tree's own coordinates: its containing mount on the
    // same device, and the path relative to that mount's root.
    let containing = mounts
        .iter()
        .filter(|mount| canonical.starts_with(&mount.point) && mount.dev == dev)
        .max_by_key(|mount| mount.point.as_os_str().len());
    let containing = containing?;
    let guarded_root = containing.root.join(
        canonical
            .strip_prefix(&containing.point)
            .expect("prefix checked"),
    );
    let mut guarded = vec![(dev, guarded_root)];
    guarded.extend(
        mounts
            .iter()
            .filter(|m| m.point.starts_with(canonical))
            .map(|m| (m.dev, m.root.clone())),
    );
    for child in child_roots {
        let containing = mounts
            .iter()
            .filter(|m| child.starts_with(&m.point))
            .max_by_key(|m| m.point.as_os_str().len());
        let Some(mount) = containing else { continue };
        let visible = mount
            .root
            .join(child.strip_prefix(&mount.point).expect("prefix checked"));
        let overlaps = |dev, path: &Path| {
            guarded.iter().any(|(device, root)| {
                dev == *device && (path.starts_with(root) || (!contained && root.starts_with(path)))
            })
        };
        if overlaps(mount.dev, &visible) {
            return Some(child.clone());
        }
        if !contained {
            for mount in mounts.iter().filter(|m| m.point.starts_with(child)) {
                if overlaps(mount.dev, &mount.root) {
                    return Some(mount.point.clone());
                }
            }
        }
    }
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn containing_mounts_and_cross_device_submounts_use_translated_ranges() {
        let mounts = vec![
            Mount {
                point: "/".into(),
                root: "/".into(),
                dev: 1,
                ino: 1,
            },
            Mount {
                point: "/alias".into(),
                root: "/home/u".into(),
                dev: 1,
                ino: 2,
            },
            Mount {
                point: "/home/u/state/nested".into(),
                root: "/".into(),
                dev: 2,
                ino: 3,
            },
            Mount {
                point: "/ws/cache".into(),
                root: "/".into(),
                dev: 2,
                ino: 3,
            },
        ];
        let guard = Path::new("/home/u/state");
        assert!(conflict_in_mounts(&["/alias/state/child".into()], guard, 1, &mounts).is_some());
        assert!(conflict_in_mounts(&["/ws".into()], guard, 1, &mounts).is_some());
        assert!(conflict_in_mounts(&["/alias/unrelated".into()], guard, 1, &mounts).is_none());
        assert!(translated_conflict(&["/home/u".into()], guard, 1, &mounts, true).is_none());
        assert!(translated_conflict(&["/alias/state".into()], guard, 1, &mounts, true).is_some());
    }

    #[test]
    fn bind_alias_of_writable_descendant_is_forbidden() {
        let mounts = vec![
            Mount {
                point: "/".into(),
                root: "/".into(),
                dev: 1,
                ino: 1,
            },
            Mount {
                point: "/config/launch".into(),
                root: "/workspace/sub".into(),
                dev: 1,
                ino: 31,
            },
            Mount {
                point: "/other".into(),
                root: "/unrelated".into(),
                dev: 1,
                ino: 41,
            },
        ];
        let ids = alias_identities(&[("/workspace".into(), 1)], &mounts).unwrap();
        assert!(ids.contains(&(1, 31)));
        assert!(!ids.contains(&(1, 41)));
        assert!(!ids.contains(&(1, 1)));
    }

    #[test]
    fn nested_mount_alias_is_forbidden() {
        let mounts = vec![
            Mount {
                point: "/".into(),
                root: "/".into(),
                dev: 1,
                ino: 1,
            },
            Mount {
                point: "/workspace/data".into(),
                root: "/".into(),
                dev: 2,
                ino: 2,
            },
            Mount {
                point: "/config/launch".into(),
                root: "/sub".into(),
                dev: 2,
                ino: 3,
            },
        ];
        let ids = alias_identities(&[("/workspace".into(), 1)], &mounts).unwrap();
        assert!(ids.contains(&(2, 3)));
    }

    /// Security 2026-09-27 (audit 4 B4): a bind of the guarded tree mounted
    /// beneath a child root is a conflict, and so is a bind of an ancestor;
    /// an unrelated mount on the same device is not.
    #[test]
    fn audit4_alias_conflict_finds_binds_of_the_guarded_tree_under_child_roots() {
        let mounts = vec![
            Mount {
                point: "/".into(),
                root: "/".into(),
                dev: 1,
                ino: 1,
            },
            Mount {
                point: "/home/u/state".into(),
                root: "/home/u/state".into(),
                dev: 1,
                ino: 2,
            },
            Mount {
                point: "/ws/alias".into(),
                root: "/home/u/state".into(),
                dev: 1,
                ino: 3,
            },
            Mount {
                point: "/ws/ancestor".into(),
                root: "/home/u".into(),
                dev: 1,
                ino: 4,
            },
            Mount {
                point: "/ws/unrelated".into(),
                root: "/elsewhere".into(),
                dev: 1,
                ino: 5,
            },
            Mount {
                point: "/other-fs".into(),
                root: "/home/u/state".into(),
                dev: 2,
                ino: 6,
            },
        ];
        let roots = vec![PathBuf::from("/ws")];
        // The bind of the state tree itself.
        assert_eq!(
            conflict_in_mounts(&roots, Path::new("/home/u/state"), 1, &mounts),
            Some(PathBuf::from("/ws/alias"))
        );
        // A bind of an ancestor reaches it too.
        assert_eq!(
            conflict_in_mounts(&roots, Path::new("/home/u/state"), 1, &mounts),
            Some(PathBuf::from("/ws/alias"))
        );
        // Nothing under a child root: no conflict (the lexical guards own
        // that case, and mounts elsewhere are not child-visible).
        assert_eq!(
            conflict_in_mounts(
                &[PathBuf::from("/elsewhere")],
                Path::new("/home/u/state"),
                1,
                &mounts
            ),
            None
        );
    }
}
