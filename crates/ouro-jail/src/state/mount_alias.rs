//! Child-writable grants viewed through another Linux mountpoint.
//!
//! A no-follow source walk sees the inode at an alias mountpoint, not the
//! grant's pathname ancestors. Mountinfo gives both mountpoints coordinates
//! in their underlying filesystem, including the root of a bind mount.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;

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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

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
}
