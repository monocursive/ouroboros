//! Parsing `/proc/self/mountinfo`.
//!
//! The read-only sweep needs the list of mounts that existed before this helper touched
//! anything, because "make everything read-only except what I just bound" is expressed as
//! a set difference and the kernel offers no other way to enumerate it. Parsing is pure
//! string work, so it lives out here where it is unit-tested on any OS rather than inside
//! the Linux-only executor where it would only ever be exercised in a container.
//!
//! The format, from `Documentation/filesystems/proc.rst`:
//!
//! ```text
//! 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//! (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)
//! ```
//!
//! Field 5 is the mount point, and the optional fields (7) are variable in number and
//! terminated by a literal `-`, which is why this cannot be a fixed-index split. Path
//! fields are octal-escaped by the kernel for space, tab, newline, and backslash.

/// One line of `mountinfo`, narrowed to what the sweep needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub id: u32,
    pub parent_id: u32,
    pub mount_point: String,
}

/// Parses the whole file, skipping any line that does not make sense rather than failing
/// the command.
///
/// A malformed line is a kernel this helper does not understand, and the safe reading of
/// "I could not parse a mount" is *not* "there is no such mount" — but it is also not
/// worth refusing to run over. The sweep's own failure mode is the backstop: a mount that
/// never appears here is never made read-only, and Landlock still denies writes to it,
/// so an unparsed line costs the `EROFS` error text, not the containment.
pub fn parse(contents: &str) -> Vec<Mount> {
    contents.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Mount> {
    let mut fields = line.split(' ');
    let id = fields.next()?.parse().ok()?;
    let parent_id = fields.next()?.parse().ok()?;
    let _major_minor = fields.next()?;
    let _root = fields.next()?;
    let mount_point = unescape(fields.next()?);

    if mount_point.is_empty() {
        return None;
    }

    Some(Mount {
        id,
        parent_id,
        mount_point,
    })
}

/// Undoes the kernel's `\OOO` octal escaping of space, tab, newline, and backslash.
///
/// A mount point containing a space is unusual and entirely legal, and treating the
/// escape as literal text would mean sweeping a path that does not exist while leaving the
/// real one writable — a silent hole with no error anywhere.
pub fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = String::with_capacity(field.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let digits = &field[i + 1..i + 4];
            if digits.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                if let Ok(value) = u8::from_str_radix(digits, 8) {
                    out.push(value as char);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }

    out
}

/// The mount points to make read-only: everything in `mounts` that is not one of
/// `keep_writable` and not beneath one of them.
///
/// Deepest first. A mount point can be shadowed by another mounted over it, and setting
/// the flag on the deeper one first means the shallower one's change cannot make the
/// deeper one unreachable before it has been narrowed.
pub fn sweep_targets(mounts: &[Mount], keep_writable: &[String]) -> Vec<String> {
    let mut targets: Vec<String> = mounts
        .iter()
        .map(|mount| mount.mount_point.clone())
        .filter(|point| {
            !keep_writable
                .iter()
                .any(|keep| crate::plan::inside(point, keep))
        })
        .collect();

    targets.sort_by(|a, b| {
        let depth = |p: &str| {
            p.trim_matches('/')
                .split('/')
                .filter(|s| !s.is_empty())
                .count()
        };
        depth(b).cmp(&depth(a)).then_with(|| a.cmp(b))
    });
    targets.dedup();
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real `mountinfo` from the container this helper's integration tests run in,
    // trimmed to the shapes that matter: a root, a nested mount, optional fields present
    // and absent, and a mount point with a space in it.
    const SAMPLE: &str = "\
2160 2159 0:465 / / rw,relatime - overlay overlay rw,lowerdir=/x,upperdir=/y
2161 2160 0:469 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
2162 2160 0:470 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
2163 2162 0:471 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k
2164 2160 0:472 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
2165 2160 254:1 /ws /work\\040dir rw,relatime master:1 - ext4 /dev/vda1 rw";

    #[test]
    fn parses_the_mount_point_past_the_variable_optional_fields() {
        let mounts = parse(SAMPLE);
        assert_eq!(mounts.len(), 6);
        assert_eq!(mounts[0].mount_point, "/");
        assert_eq!(mounts[0].id, 2160);
        assert_eq!(mounts[0].parent_id, 2159);
        assert_eq!(mounts[3].mount_point, "/dev/shm");
        // The line with `master:1` has one more optional field than the others; a
        // fixed-index split would have read `-` as the mount point here.
        assert_eq!(mounts[5].mount_point, "/work dir");
    }

    #[test]
    fn unescapes_the_four_characters_the_kernel_escapes() {
        assert_eq!(unescape("/a\\040b"), "/a b");
        assert_eq!(unescape("/a\\011b"), "/a\tb");
        assert_eq!(unescape("/a\\012b"), "/a\nb");
        assert_eq!(unescape("/a\\134b"), "/a\\b");
        assert_eq!(unescape("/plain/path"), "/plain/path");
        // Not an escape: left alone rather than mangled.
        assert_eq!(unescape("/a\\9zb"), "/a\\9zb");
        assert_eq!(unescape("/trailing\\"), "/trailing\\");
    }

    #[test]
    fn a_malformed_line_is_skipped_not_fatal() {
        let mounts = parse("garbage\n\n2160 2159 0:465 / / rw - overlay overlay rw");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mount_point, "/");
    }

    #[test]
    fn the_sweep_keeps_dev_and_proc_and_everything_under_them() {
        let mounts = parse(SAMPLE);
        let keep = vec!["/dev".to_string(), "/proc".to_string()];
        let targets = sweep_targets(&mounts, &keep);

        assert!(!targets.contains(&"/proc".to_string()));
        assert!(!targets.contains(&"/dev".to_string()));
        // `/dev/shm` is a separate mount and would be swept on its own if the filter were
        // an equality test rather than a containment test.
        assert!(!targets.contains(&"/dev/shm".to_string()));
        assert!(targets.contains(&"/".to_string()));
        assert!(targets.contains(&"/sys".to_string()));
        assert!(targets.contains(&"/work dir".to_string()));
    }

    #[test]
    fn the_sweep_runs_deepest_first() {
        let mounts = parse(SAMPLE);
        let targets = sweep_targets(&mounts, &[]);
        let root = targets.iter().position(|p| p == "/").unwrap();
        let shm = targets.iter().position(|p| p == "/dev/shm").unwrap();
        assert!(shm < root, "{targets:?}");
    }

    #[test]
    fn keep_writable_is_component_wise() {
        let mounts = parse("1 0 0:1 / /devices rw - t t rw");
        // `/devices` merely starts with the string `/dev`.
        assert_eq!(
            sweep_targets(&mounts, &["/dev".to_string()]),
            vec!["/devices".to_string()]
        );
    }
}
