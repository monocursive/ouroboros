//! The arguments an entry stop snapshots from the tracee: flags, pathnames,
//! directory fds and a socket address, as the closed-set row names them.

use libc::pid_t;

use super::Session;
use super::seams::path_has_marker;
use super::tasks::Pending;
use crate::platform::linux::tracer::closed_set::{self, ClosedOp, Entry, FlagSource};
use crate::platform::linux::tracer::{Args, PathSnapshot, SockaddrSnapshot, sys};

impl Session {
    /// The flags word of a row, and whether flags the consumer needs for
    /// classification could not be decoded.
    pub(super) fn capture_flags(
        &mut self,
        tid: pid_t,
        entry: &'static Entry,
        raw: &[u64; 6],
    ) -> (Option<u64>, bool) {
        match entry.flags {
            FlagSource::None => (None, false),
            FlagSource::Arg(index) => (Some(raw[index as usize]), false),
            FlagSource::ImpliedCreat => (Some(closed_set::implied_creat_flags()), false),
            FlagSource::OpenHow { ptr, size } => {
                // `open_how` is { u64 flags; u64 mode; u64 resolve; }. A
                // caller that passes a smaller size gets EINVAL from the
                // kernel and gives us nothing to decode.
                const OPEN_HOW_VER0: u64 = 24;
                if raw[size as usize] < OPEN_HOW_VER0 {
                    return (None, true);
                }
                let mut word = [0u8; 8];
                if sys::read_remote(tid, raw[ptr as usize], &mut word) == 8 {
                    (Some(u64::from_ne_bytes(word)), false)
                } else {
                    (None, true)
                }
            }
        }
    }

    /// Read the pathnames, directory fds and socket address the row names.
    pub(super) fn capture_paths(
        &mut self,
        tid: pid_t,
        entry: &'static Entry,
        raw: &[u64; 6],
    ) -> Pending {
        let mut args = Args::default();
        let mut path_unreadable = false;
        let mut path2_unreadable = false;
        let mut sockaddr_unreadable = false;
        if let Some(index) = entry.path {
            let (snapshot, unreadable) = self.read_path(tid, raw[index as usize]);
            args.path = snapshot;
            path_unreadable = unreadable;
        }
        // O03 seam: force this covered call's path to be
        // kernel-accepted-but-unreadable — the truncation case O03 names —
        // when its path matches the seam marker. Gated to a non-exec op (an
        // exec never returns to the normal exit path where a `path_unreadable`
        // gap is emitted). When the call then succeeds it becomes a
        // `path_unreadable` gap.
        if entry.op != ClosedOp::Exec
            && let Some(marker) = &self.force_truncate_marker
            && path_has_marker(args.path.as_ref(), marker)
        {
            args.path = Some(PathSnapshot {
                bytes: Vec::new(),
                complete: false,
            });
            path_unreadable = true;
        }
        if let Some(index) = entry.path2 {
            let (snapshot, unreadable) = self.read_path(tid, raw[index as usize]);
            args.path2 = snapshot;
            path2_unreadable = unreadable;
        }
        if let Some(index) = entry.dirfd {
            args.dirfd = Some(raw[index as usize] as i32);
        }
        if let Some(index) = entry.dirfd2 {
            args.dirfd2 = Some(raw[index as usize] as i32);
        }
        // §11.3: a relative pathname the kernel resolves against
        // the thread's own cwd is resolved against that cwd at
        // classification; the snapshot itself stays the raw argument, so the
        // exit-side stability check compares what the tracee still holds.
        args.cwd = self.observed_cwd(tid, args.path.as_ref(), args.path2.as_ref());
        if let Some((ptr, len)) = entry.sockaddr {
            let (snapshot, unreadable) =
                self.read_sockaddr(tid, raw[ptr as usize], raw[len as usize]);
            args.sockaddr = snapshot;
            sockaddr_unreadable = unreadable;
        }
        Pending {
            path_unreadable,
            path2_unreadable,
            sockaddr_unreadable,
            ..Pending::new(entry, args, *raw)
        }
    }

    /// The stopped thread's working directory, read from `/proc/<tid>/cwd`,
    /// when one of the call's path arguments is a complete relative pathname
    /// the kernel resolves against it (§11.3). The true dirfd cases
    /// resolve against their descriptor instead and read nothing.
    fn observed_cwd(
        &self,
        tid: pid_t,
        path: Option<&PathSnapshot>,
        path2: Option<&PathSnapshot>,
    ) -> Option<Box<[u8]>> {
        let relative = |snapshot: Option<&PathSnapshot>| {
            snapshot.is_some_and(|snapshot| {
                snapshot.complete && snapshot.bytes.first().is_some_and(|byte| *byte != b'/')
            })
        };
        if !relative(path) && !relative(path2) {
            return None;
        }
        self.procfs
            .cwd(tid)
            .filter(|bytes| bytes.first() == Some(&b'/'))
            .map(Vec::into_boxed_slice)
    }

    /// A NUL-terminated pathname argument, bounded by `path_snapshot_max`.
    ///
    /// `complete` is false when the bytes ran out before a NUL or when the
    /// tracee's memory could not be read: §11.3 wants the weaker assertion
    /// carried in band, not a shorter path presented as the whole one. The
    /// second return says nothing was readable at all, which the syscall exit
    /// classifies once the kernel's own verdict on the same pointer is known.
    fn read_path(&mut self, tid: pid_t, addr: u64) -> (Option<PathSnapshot>, bool) {
        if addr == 0 {
            return (None, false);
        }
        let max = self.config.path_snapshot_max;
        let mut bytes: Vec<u8> = Vec::new();
        while bytes.len() < max {
            let offset = bytes.len();
            let at = addr.wrapping_add(offset as u64);
            let chunk_size = if offset == 0 { 256 } else { self.scratch.len() };
            let want = (max - offset)
                .min(chunk_size)
                .min(4096 - (at % 4096) as usize);
            let read = sys::read_remote(tid, at, &mut self.scratch[..want]);
            if read == 0 {
                if bytes.is_empty() {
                    return (
                        Some(PathSnapshot {
                            bytes,
                            complete: false,
                        }),
                        true,
                    );
                }
                self.summary.loss.path_truncated += 1;
                return (
                    Some(PathSnapshot {
                        bytes,
                        complete: false,
                    }),
                    false,
                );
            }
            let chunk = &self.scratch[..read];
            if let Some(end) = chunk.iter().position(|b| *b == 0) {
                bytes.extend_from_slice(&chunk[..end]);
                return (
                    Some(PathSnapshot {
                        bytes,
                        complete: true,
                    }),
                    false,
                );
            }
            bytes.extend_from_slice(chunk);
        }
        self.summary.loss.path_truncated += 1;
        (
            Some(PathSnapshot {
                bytes,
                complete: false,
            }),
            false,
        )
    }

    /// The `sockaddr` of a `connect`, as far as the closed set describes it.
    ///
    /// The address bytes are read — the family's own size, never the length
    /// the caller declared, which is a claim and not a fact — only to decide
    /// whether the whole address was readable, and are not retained: the
    /// record names the family and the completeness of the claim, and §11.1
    /// forbids collecting argument memory nothing downstream will ever see.
    /// For a family the set does not name, only the family is read.
    fn read_sockaddr(
        &mut self,
        tid: pid_t,
        addr: u64,
        len: u64,
    ) -> (Option<SockaddrSnapshot>, bool) {
        if addr == 0 {
            return (None, false);
        }
        let unknown = SockaddrSnapshot {
            family: None,
            complete: false,
        };
        if len < 2 {
            // The kernel rejects this too; there is no family to read.
            return (Some(unknown), false);
        }
        if sys::read_remote(tid, addr, &mut self.scratch[..2]) < 2 {
            return (Some(unknown), true);
        }
        let family = u16::from_ne_bytes([self.scratch[0], self.scratch[1]]);
        let Some(family_len) = sockaddr_len(family, len) else {
            return (
                Some(SockaddrSnapshot {
                    family: Some(family),
                    complete: false,
                }),
                false,
            );
        };
        let want = family_len.min(self.scratch.len());
        let read = sys::read_remote(tid, addr, &mut self.scratch[..want]);
        (
            Some(SockaddrSnapshot {
                family: Some(family),
                // Complete means the whole address of this family was read
                // and the caller declared at least that much, which
                // `sockaddr_len` has already bounded by the claim.
                complete: read == want,
            }),
            read == 0,
        )
    }
}

/// How many bytes of a `sockaddr` belong to its family, bounded by what the
/// caller declared. This is what is read to decide whether the whole address
/// was readable, and no more than that is ever touched. `None` for a family
/// the closed set does not name.
fn sockaddr_len(family: u16, declared: u64) -> Option<usize> {
    let size = match i32::from(family) {
        libc::AF_INET => 16,
        libc::AF_INET6 => 28,
        // `sockaddr_un` is 110 bytes; an abstract or short name uses less,
        // and only the caller's length says how much of it is the name.
        libc::AF_UNIX => 110,
        _ => return None,
    };
    Some(size.min(usize::try_from(declared).unwrap_or(usize::MAX)))
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::*;

    #[test]
    fn path_reads_preserve_page_boundaries_long_names_and_terminator_checks() {
        let (mut session, _rx) = stalled_session();
        let pid = std::process::id() as pid_t;
        // Page-aligned, live memory followed by a deliberately unreadable page.
        // SAFETY: anonymous mapping; every access below stays in its first page.
        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                8192,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(memory, libc::MAP_FAILED);
        struct Mapping(*mut libc::c_void);
        impl Drop for Mapping {
            fn drop(&mut self) {
                // SAFETY: this test owns the entire mapping until drop.
                unsafe {
                    libc::munmap(self.0, 8192);
                }
            }
        }
        let mapping = Mapping(memory);
        // SAFETY: the second page is inside the mapping and has no Rust refs.
        let protected = unsafe { libc::mprotect(memory.add(4096), 4096, libc::PROT_NONE) };
        assert_eq!(protected, 0);
        // SAFETY: the first page remains writable and is exclusively owned.
        let page = unsafe { std::slice::from_raw_parts_mut(mapping.0.cast::<u8>(), 4096) };
        for length in [0, 1, 255, 256, 257, 1024, 4095] {
            let start = 4095 - length;
            page[start..4095].fill(b'x');
            page[4095] = 0;
            let addr = page[start..].as_ptr() as u64;
            let expected = vec![b'x'; length];
            let (snapshot, unreadable) = session.read_path(pid, addr);
            let snapshot = snapshot.unwrap();
            assert!(!unreadable && snapshot.complete);
            assert_eq!(snapshot.bytes, expected);
            assert!(session.path_unchanged(pid, addr, &expected));
            page[4095] = b'y';
            assert!(
                !session.path_unchanged(pid, addr, &expected),
                "changed NUL at length {length}"
            );
            let (snapshot, _) = session.read_path(pid, addr);
            assert!(
                !snapshot.unwrap().complete,
                "no terminator before unreadable memory"
            );
        }
        assert!(!session.path_unchanged(pid, 0, b""));
        assert!(!session.path_unchanged(pid, u64::MAX, b"x"));
    }

    #[test]
    fn a_sockaddr_is_clamped_to_its_family_not_the_callers_claim() {
        // A sockaddr_in announced as 128 bytes is still 16 bytes of address.
        assert_eq!(sockaddr_len(libc::AF_INET as u16, 128), Some(16));
        assert_eq!(sockaddr_len(libc::AF_INET as u16, 0x7fff_ffff), Some(16));
        // A claim shorter than the family's size bounds it further: the
        // kernel would reject the call, and nothing beyond the claim is ours.
        assert_eq!(sockaddr_len(libc::AF_INET as u16, 8), Some(8));
        assert_eq!(sockaddr_len(libc::AF_INET6 as u16, 128), Some(28));
        assert_eq!(sockaddr_len(libc::AF_UNIX as u16, 128), Some(110));
        assert_eq!(sockaddr_len(libc::AF_UNIX as u16, 20), Some(20));
        // A family the closed set does not name keeps no bytes at all.
        assert_eq!(sockaddr_len(libc::AF_NETLINK as u16, 128), None);
        assert_eq!(sockaddr_len(libc::AF_PACKET as u16, 128), None);
        assert_eq!(sockaddr_len(0xffff, 128), None);
    }
}
