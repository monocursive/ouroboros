//! `linux-closed-v1`: the nineteen x86_64 syscalls of jail-v1 §11.2 and the
//! shape of the arguments the observer reads from each one.
//!
//! The table is the module's single source of truth. The narrowing filter
//! ([`super::filter`]) turns it into `SECCOMP_RET_TRACE` numbers, and the
//! tracer thread uses the same rows to decide which argument is a pathname,
//! which is a directory fd and where the flags live. A syscall not in this
//! table is not observed and is not claimed to be.

/// The operation families the consumer maps onto the §11.2 audit rows.
///
/// `Open` does not say `fs.create` or `fs.write`: that distinction is made
/// from [`Args::flags`](super::Args::flags) by the consumer, exactly as
/// §11.2 requires ("An O_CREAT open emits one `fs.create`, otherwise a
/// mutation open emits one `fs.write`"). The tracer never emits an `Open`
/// for a read-only open at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ClosedOp {
    Exec,
    Open,
    Rename,
    Unlink,
    Rmdir,
    Mkdir,
    Link,
    Symlink,
    Connect,
}

impl ClosedOp {
    /// Every variant, for callers that count per operation.
    pub const ALL: [ClosedOp; 9] = [
        ClosedOp::Exec,
        ClosedOp::Open,
        ClosedOp::Rename,
        ClosedOp::Unlink,
        ClosedOp::Rmdir,
        ClosedOp::Mkdir,
        ClosedOp::Link,
        ClosedOp::Symlink,
        ClosedOp::Connect,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ClosedOp::Exec => "exec",
            ClosedOp::Open => "open",
            ClosedOp::Rename => "rename",
            ClosedOp::Unlink => "unlink",
            ClosedOp::Rmdir => "rmdir",
            ClosedOp::Mkdir => "mkdir",
            ClosedOp::Link => "link",
            ClosedOp::Symlink => "symlink",
            ClosedOp::Connect => "connect",
        }
    }
}

/// Where the flags of a row come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagSource {
    /// The call carries no flags word worth recording. `mkdir` and
    /// `mkdirat` are here: their numeric argument is a mode, and recording a
    /// mode in a field named `flags` would misdescribe it.
    None,
    /// Register `n` is the flags word.
    Arg(u8),
    /// `creat`: the kernel defines it as `open(path, O_CREAT|O_WRONLY|O_TRUNC,
    /// mode)`, so the flags are the syscall itself rather than an argument.
    ImpliedCreat,
    /// `openat2`: argument `ptr` points at a `struct open_how` of `size`
    /// bytes given by argument `size`. Only `open_how.flags` is decoded, and
    /// only when the caller passed at least a whole `open_how` (§11.2:
    /// "`openat2` requires decoding only the supported size/flags").
    OpenHow { ptr: u8, size: u8 },
}

/// One row of the closed set.
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    pub nr: u64,
    pub name: &'static str,
    pub op: ClosedOp,
    /// Argument index of the directory fd that `path` is resolved against.
    pub dirfd: Option<u8>,
    /// Argument index of the primary pathname pointer.
    pub path: Option<u8>,
    /// Argument index of the directory fd that `path2` is resolved against.
    pub dirfd2: Option<u8>,
    /// Argument index of the second pathname pointer, for two-path calls.
    pub path2: Option<u8>,
    pub flags: FlagSource,
    /// `(pointer argument, length argument)` of a socket address.
    pub sockaddr: Option<(u8, u8)>,
}

/// `(directory fd argument, pathname argument)`, either of which a given
/// call may not have.
type At = (Option<u8>, Option<u8>);

const fn row(
    nr: u64,
    name: &'static str,
    op: ClosedOp,
    first: At,
    second: At,
    flags: FlagSource,
) -> Entry {
    Entry {
        nr,
        name,
        op,
        dirfd: first.0,
        path: first.1,
        dirfd2: second.0,
        path2: second.1,
        flags,
        sockaddr: None,
    }
}

/// The closed set on x86_64.
///
/// The `flags` of `creat` are implied and the `mode` arguments of `mkdir`,
/// `mkdirat`, `open`-family and `openat2` are deliberately not recorded:
/// §11.2 covers the decision to open for mutation, not the permissions the
/// caller asked for.
///
/// Laid out one row per line on purpose: the table is the thing a reviewer
/// checks against jail-v1 §11.2, so it is exempt from reformatting.
#[rustfmt::skip]
pub const CLOSED_SET: &[Entry] = &[
    // proc.exec
    row(59, "execve", ClosedOp::Exec, (None, Some(0)), (None, None), FlagSource::None),
    row(322, "execveat", ClosedOp::Exec, (Some(0), Some(1)), (None, None), FlagSource::Arg(4)),
    // fs.create / fs.write, decided from the flags by the consumer
    row(2, "open", ClosedOp::Open, (None, Some(0)), (None, None), FlagSource::Arg(1)),
    row(257, "openat", ClosedOp::Open, (Some(0), Some(1)), (None, None), FlagSource::Arg(2)),
    row(437, "openat2", ClosedOp::Open, (Some(0), Some(1)), (None, None), FlagSource::OpenHow { ptr: 2, size: 3 }),
    row(85, "creat", ClosedOp::Open, (None, Some(0)), (None, None), FlagSource::ImpliedCreat),
    // fs.rename
    row(82, "rename", ClosedOp::Rename, (None, Some(0)), (None, Some(1)), FlagSource::None),
    row(264, "renameat", ClosedOp::Rename, (Some(0), Some(1)), (Some(2), Some(3)), FlagSource::None),
    row(316, "renameat2", ClosedOp::Rename, (Some(0), Some(1)), (Some(2), Some(3)), FlagSource::Arg(4)),
    // fs.unlink
    row(87, "unlink", ClosedOp::Unlink, (None, Some(0)), (None, None), FlagSource::None),
    row(263, "unlinkat", ClosedOp::Unlink, (Some(0), Some(1)), (None, None), FlagSource::Arg(2)),
    row(84, "rmdir", ClosedOp::Rmdir, (None, Some(0)), (None, None), FlagSource::None),
    // fs.create through directory entries
    row(83, "mkdir", ClosedOp::Mkdir, (None, Some(0)), (None, None), FlagSource::None),
    row(258, "mkdirat", ClosedOp::Mkdir, (Some(0), Some(1)), (None, None), FlagSource::None),
    row(86, "link", ClosedOp::Link, (None, Some(0)), (None, Some(1)), FlagSource::None),
    row(265, "linkat", ClosedOp::Link, (Some(0), Some(1)), (Some(2), Some(3)), FlagSource::Arg(4)),
    // symlink(target, linkpath) and symlinkat(target, newdirfd, linkpath):
    // the target is a string the kernel stores, not a path it resolves, so it
    // has no directory fd. The link path does.
    row(88, "symlink", ClosedOp::Symlink, (None, Some(0)), (None, Some(1)), FlagSource::None),
    row(266, "symlinkat", ClosedOp::Symlink, (None, Some(0)), (Some(1), Some(2)), FlagSource::None),
    // net.connect
    Entry {
        nr: 42,
        name: "connect",
        op: ClosedOp::Connect,
        dirfd: None,
        path: None,
        dirfd2: None,
        path2: None,
        flags: FlagSource::None,
        sockaddr: Some((1, 2)),
    },
];

/// The row for a syscall number, or `None` when the number is outside the
/// closed set.
#[must_use]
pub fn lookup(nr: u64) -> Option<&'static Entry> {
    CLOSED_SET.iter().find(|entry| entry.nr == nr)
}

/// `O_CREAT|O_WRONLY|O_TRUNC`, the flags `creat` is defined as.
#[must_use]
pub fn implied_creat_flags() -> u64 {
    (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64
}

/// Whether an open-family call asks for something the closed set covers.
///
/// §11.2 covers `open`, `openat`, `openat2` and `creat` "requesting
/// write/create/truncate". A read-only open is outside the set: it is not a
/// lost event and does not degrade coverage ("Operations explicitly outside
/// the closed set are not lost events").
#[must_use]
pub fn open_is_covered(flags: u64) -> bool {
    let accmode = flags & (libc::O_ACCMODE as u64);
    accmode != (libc::O_RDONLY as u64) || (flags & ((libc::O_CREAT | libc::O_TRUNC) as u64)) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_set_has_exactly_the_nineteen_rows_of_the_spec() {
        assert_eq!(CLOSED_SET.len(), 19);
        let numbers: BTreeSet<u64> = CLOSED_SET.iter().map(|e| e.nr).collect();
        assert_eq!(numbers.len(), 19, "no syscall number may appear twice");
        let expected: BTreeSet<u64> = [
            59, 322, 2, 257, 437, 85, 82, 264, 316, 87, 263, 84, 83, 258, 86, 265, 88, 266, 42,
        ]
        .into_iter()
        .collect();
        assert_eq!(numbers, expected);
        let names: BTreeSet<&str> = CLOSED_SET.iter().map(|e| e.name).collect();
        assert_eq!(names.len(), 19, "no syscall name may appear twice");
    }

    /// The table must agree with the `SYS_*` numbers of this target, which is
    /// the only cross-check that catches a transposed digit.
    #[test]
    fn numbers_match_the_targets_syscall_table() {
        let expected: &[(&str, u64)] = &[
            ("execve", libc::SYS_execve as u64),
            ("execveat", libc::SYS_execveat as u64),
            ("open", libc::SYS_open as u64),
            ("openat", libc::SYS_openat as u64),
            ("creat", libc::SYS_creat as u64),
            ("rename", libc::SYS_rename as u64),
            ("renameat", libc::SYS_renameat as u64),
            ("renameat2", libc::SYS_renameat2 as u64),
            ("unlink", libc::SYS_unlink as u64),
            ("unlinkat", libc::SYS_unlinkat as u64),
            ("rmdir", libc::SYS_rmdir as u64),
            ("mkdir", libc::SYS_mkdir as u64),
            ("mkdirat", libc::SYS_mkdirat as u64),
            ("link", libc::SYS_link as u64),
            ("linkat", libc::SYS_linkat as u64),
            ("symlink", libc::SYS_symlink as u64),
            ("symlinkat", libc::SYS_symlinkat as u64),
            ("connect", libc::SYS_connect as u64),
        ];
        for (name, nr) in expected {
            let entry = CLOSED_SET.iter().find(|e| e.name == *name).expect(name);
            assert_eq!(entry.nr, *nr, "{name}");
            assert_eq!(lookup(*nr).map(|e| e.name), Some(*name));
        }
        // openat2 is number 437 on every architecture that has it; libc does
        // not always export SYS_openat2, so it is checked against the value
        // the kernel's syscall table fixes.
        assert_eq!(lookup(437).map(|e| e.name), Some("openat2"));
    }

    #[test]
    fn nothing_outside_the_set_resolves() {
        assert!(lookup(0).is_none(), "read is not in the closed set");
        assert!(lookup(1).is_none(), "write is not in the closed set");
        assert!(lookup(9).is_none(), "mmap is not in the closed set");
        assert!(lookup(u64::from(u32::MAX)).is_none());
    }

    #[test]
    fn two_path_rows_carry_both_paths_and_their_directory_fds() {
        for name in [
            "rename",
            "renameat",
            "renameat2",
            "link",
            "linkat",
            "symlink",
            "symlinkat",
        ] {
            let e = CLOSED_SET.iter().find(|e| e.name == name).expect(name);
            assert!(
                e.path.is_some() && e.path2.is_some(),
                "{name} must snapshot both paths"
            );
            assert_ne!(e.path, e.path2, "{name} must read two different arguments");
        }
        let renameat = CLOSED_SET.iter().find(|e| e.name == "renameat").unwrap();
        assert_eq!((renameat.dirfd, renameat.dirfd2), (Some(0), Some(2)));
        // symlink's target is stored, not resolved, so it has no dirfd; the
        // link path is resolved against newdirfd.
        let symlinkat = CLOSED_SET.iter().find(|e| e.name == "symlinkat").unwrap();
        assert_eq!((symlinkat.dirfd, symlinkat.dirfd2), (None, Some(1)));
    }

    #[test]
    fn open_coverage_follows_the_spec_table() {
        let rdonly = libc::O_RDONLY as u64;
        assert!(
            !open_is_covered(rdonly),
            "a read-only open is outside the set"
        );
        assert!(
            !open_is_covered(rdonly | libc::O_CLOEXEC as u64),
            "O_CLOEXEC changes nothing"
        );
        assert!(
            !open_is_covered(rdonly | libc::O_DIRECTORY as u64),
            "opening a directory to read it"
        );
        assert!(open_is_covered(libc::O_WRONLY as u64));
        assert!(open_is_covered(libc::O_RDWR as u64));
        assert!(
            open_is_covered(rdonly | libc::O_CREAT as u64),
            "O_CREAT|O_RDONLY still creates"
        );
        assert!(
            open_is_covered(rdonly | libc::O_TRUNC as u64),
            "O_TRUNC mutates"
        );
        assert!(open_is_covered(implied_creat_flags()));
    }

    #[test]
    fn implied_creat_flags_are_what_creat_means() {
        let f = implied_creat_flags();
        assert_eq!(f & (libc::O_ACCMODE as u64), libc::O_WRONLY as u64);
        assert_ne!(f & (libc::O_CREAT as u64), 0);
        assert_ne!(f & (libc::O_TRUNC as u64), 0);
    }
}
