//! `NETLINK_SOCK_DIAG` for AF_UNIX, the identity half of the N05 mechanism.
//!
//! jail-v1 §10 ("Network namespaces alone do not isolate pathname AF_UNIX
//! sockets in shared mounts") and CONTRACT §3.4. The unix-peer mediator, given
//! a pathname the child asked to connect to, must decide whether a listener
//! bound to *that node's filesystem identity* exists **in the attempt's own
//! network namespace**. A host-created socket, even one bind-mounted or
//! hard-linked into a child-visible directory, is bound in the host netns and
//! so is absent from this dump; an attempt-created listener is present. That
//! netns scoping, plus the VFS-identity match below, is what distinguishes the
//! two (spike `unixpeer-spike-2026-09-22-ouro-ci.txt` §3, §3a).
//!
//! The kernel reports a bound socket's filesystem identity as
//! `UNIX_DIAG_VFS = (udiag_vfs_ino: u32, udiag_vfs_dev: u32)`, where the dev is
//! the *kernel-internal* `dev_t` (`major << 20 | minor`), not the userspace
//! `st_dev`, and the inode is only 32 bits wide. The match rule and its
//! refusal for inodes beyond `u32::MAX` live in [`VfsId`]. This width is a real
//! boundary: tmpfs with `inode64`, xfs and btrfs can issue inodes at or above
//! `2^32`, and such a node cannot be proven identical through this interface,
//! so it is denied rather than guessed (spike §3a).
//!
//! The wire parsing is a pure function, [`parse_dump`], tested against a
//! hand-built buffer; only [`SockDiag`]'s methods call the kernel.

use std::io;

/// `SOCK_DIAG_BY_FAMILY`.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// `NLMSG_ERROR`.
const NLMSG_ERROR: u16 = 2;
/// `NLMSG_DONE`.
const NLMSG_DONE: u16 = 3;
/// `NLM_F_REQUEST | NLM_F_DUMP`.
const NLM_F_REQUEST_DUMP: u16 = 0x0001 | 0x0300;
/// `UNIX_DIAG_VFS` attribute type.
const UNIX_DIAG_VFS: u16 = 1;

/// `UDIAG_SHOW_VFS`: request the on-disk inode/dev of a pathname socket.
/// It is the only attribute requested: the identity match needs nothing
/// else, and every other one (the bound name above all) would be copied for
/// every socket of the namespace on each mediated connect.
pub const UDIAG_SHOW_VFS: u32 = 0x0000_0002;

// The wire layouts, as offsets into a received buffer.
/// `struct nlmsghdr`: `nlmsg_len` (u32), `nlmsg_type` (u16), `nlmsg_flags`
/// (u16), `nlmsg_seq` (u32), `nlmsg_pid` (u32).
const NLMSG_HDRLEN: usize = 16;
const NLMSG_LEN_AT: usize = 0;
const NLMSG_TYPE_AT: usize = 4;
const NLMSG_SEQ_AT: usize = 8;
/// `struct nlmsgerr` begins with the `error` (i32) right after the header.
const NLMSGERR_ERROR_AT: usize = NLMSG_HDRLEN;
/// `struct unix_diag_msg`: `udiag_family`, `udiag_type`, `udiag_state`,
/// `pad` (u8 each), `udiag_ino` (u32), `udiag_cookie` (2 x u32); its
/// attributes follow.
const UNIX_DIAG_MSG_LEN: usize = 16;
const UDIAG_STATE_AT: usize = 2;
/// `struct nlattr`: `nla_len` (u16), `nla_type` (u16); the payload follows.
const NLA_HDRLEN: usize = 4;
const NLA_LEN_AT: usize = 0;
const NLA_TYPE_AT: usize = 2;
/// The `nla_type` bits that are the type, without `NLA_F_NESTED` and
/// `NLA_F_NET_BYTEORDER`.
const NLA_TYPE_MASK: u16 = 0x3fff;
/// `UNIX_DIAG_VFS`'s payload: `udiag_vfs_ino` (u32), `udiag_vfs_dev` (u32).
const UNIX_DIAG_VFS_INO_AT: usize = 0;
const UNIX_DIAG_VFS_DEV_AT: usize = 4;
const UNIX_DIAG_VFS_LEN: usize = 8;

/// A malformed reply: never read as "no such listener".
fn malformed(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// `N` bytes at `at` in `buf`, or a malformed reply.
fn bytes_at<const N: usize>(buf: &[u8], at: usize) -> io::Result<[u8; N]> {
    at.checked_add(N)
        .and_then(|end| buf.get(at..end))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| malformed("sock_diag: a field runs past its message"))
}

fn u16_at(buf: &[u8], at: usize) -> io::Result<u16> {
    bytes_at(buf, at).map(u16::from_ne_bytes)
}

fn u32_at(buf: &[u8], at: usize) -> io::Result<u32> {
    bytes_at(buf, at).map(u32::from_ne_bytes)
}

fn i32_at(buf: &[u8], at: usize) -> io::Result<i32> {
    bytes_at(buf, at).map(i32::from_ne_bytes)
}

/// `len` rounded up to the 4-byte netlink alignment (`NLMSG_ALIGN`,
/// `NLA_ALIGN`).
fn align4(len: usize) -> usize {
    (len + 3) & !3
}

/// `TCP_LISTEN`, the `st_state` value a bound, listening socket reports.
pub const SS_LISTEN: u8 = 10;

/// The filesystem identity of a bound pathname socket, as sock_diag reports it.
///
/// Constructed from a `stat` with [`VfsId::from_stat`], which encodes the
/// userspace `st_dev` into the kernel's `major << 20 | minor` form and refuses
/// an inode wider than the interface can represent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VfsId {
    /// The inode number (32-bit on the wire).
    pub ino: u32,
    /// The kernel-internal device number (`major << 20 | minor`).
    pub dev: u32,
}

impl VfsId {
    /// Encode a userspace device number the way `UNIX_DIAG_VFS` reports it:
    /// `major << 20 | minor`. This form was confirmed against real sock_diag
    /// output on the reference host (ext4 `st_dev` 2049 -> 8388609; spike §3a).
    #[must_use]
    pub fn encode_dev(st_dev: u64) -> u32 {
        (dev_major(st_dev) << 20) | (dev_minor(st_dev) & 0x000f_ffff)
    }

    /// The VFS identity of a node the mediator has `stat`ed, or `None` when the
    /// node's inode is too wide for this interface to represent — in which case
    /// identity cannot be proven and the mediator must deny.
    #[must_use]
    pub fn from_stat(st_ino: u64, st_dev: u64) -> Option<Self> {
        let ino = u32::try_from(st_ino).ok()?;
        Some(Self {
            ino,
            dev: Self::encode_dev(st_dev),
        })
    }
}

/// Major of a userspace `dev_t`, the same decomposition as `libc::major`,
/// written out so the module builds and its pure tests run on any host.
fn dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff_u64)) as u32
}

/// Minor of a userspace `dev_t`, matching `libc::minor`.
fn dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff_u64)) as u32
}

/// One socket from a unix `sock_diag` dump: what the identity match reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The TCP-style state; [`SS_LISTEN`] for a listening socket.
    pub state: u8,
    /// `UNIX_DIAG_VFS`, present only for a *bound pathname* socket and only
    /// when `UDIAG_SHOW_VFS` was requested.
    pub vfs: Option<VfsId>,
}

/// Parse a sequence of received netlink bytes into unix `sock_diag` entries,
/// appended to `out`.
///
/// Pure: it performs no I/O and is the unit under test. It rejects a truncated
/// message, an attribute that runs past its message, a sequence mismatch and a
/// `NLMSG_ERROR`, rather than skipping quietly — a short read must not look
/// like "no such listener".
///
/// Returns `Ok(false)` when the buffer did not contain the `NLMSG_DONE`
/// marker (the caller must read more), or `Ok(true)` when the dump ended.
///
/// # Errors
///
/// [`io::Error`] for a malformed message, a sequence mismatch, or the errno of
/// a `NLMSG_ERROR` reply.
pub fn parse_dump(buf: &[u8], expect_seq: u32, out: &mut Vec<Entry>) -> io::Result<bool> {
    let mut off = 0usize;
    while off + NLMSG_HDRLEN <= buf.len() {
        let message = &buf[off..];
        let len = usize::try_from(u32_at(message, NLMSG_LEN_AT)?)
            .map_err(|_| malformed("sock_diag: truncated netlink message"))?;
        if len < NLMSG_HDRLEN || len > message.len() {
            return Err(malformed("sock_diag: truncated netlink message"));
        }
        let message = &message[..len];
        if u32_at(message, NLMSG_SEQ_AT)? != expect_seq {
            return Err(malformed("sock_diag: sequence mismatch"));
        }
        match u16_at(message, NLMSG_TYPE_AT)? {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let err = i32_at(message, NLMSGERR_ERROR_AT)
                    .map_err(|_| malformed("sock_diag: truncated netlink error"))?;
                if err == 0 {
                    return Ok(true); // an ACK, treated as a clean end
                }
                return Err(io::Error::from_raw_os_error(-err));
            }
            SOCK_DIAG_BY_FAMILY => out.push(parse_unix_msg(&message[NLMSG_HDRLEN..])?),
            _ => {}
        }
        off += align4(len);
    }
    Ok(false)
}

/// Parse one `unix_diag_msg` and its attributes.
fn parse_unix_msg(body: &[u8]) -> io::Result<Entry> {
    if body.len() < UNIX_DIAG_MSG_LEN {
        return Err(malformed("sock_diag: short unix_diag_msg"));
    }
    let mut entry = Entry {
        state: body[UDIAG_STATE_AT],
        vfs: None,
    };
    let mut at = UNIX_DIAG_MSG_LEN;
    while at + NLA_HDRLEN <= body.len() {
        let attribute = &body[at..];
        let len = usize::from(u16_at(attribute, NLA_LEN_AT)?);
        if len < NLA_HDRLEN || len > attribute.len() {
            return Err(malformed("sock_diag: attribute runs past its message"));
        }
        let payload = &attribute[NLA_HDRLEN..len];
        if u16_at(attribute, NLA_TYPE_AT)? & NLA_TYPE_MASK == UNIX_DIAG_VFS
            && payload.len() >= UNIX_DIAG_VFS_LEN
        {
            entry.vfs = Some(VfsId {
                ino: u32_at(payload, UNIX_DIAG_VFS_INO_AT)?,
                dev: u32_at(payload, UNIX_DIAG_VFS_DEV_AT)?,
            });
        }
        at += align4(len);
    }
    Ok(entry)
}

/// Whether `entries` contains a *listening* socket whose VFS identity is `want`.
///
/// Pure, so the identity decision is tested without a kernel: a non-listening
/// socket, or one whose VFS identity differs, is not a match.
#[must_use]
pub fn has_listener_for(entries: &[Entry], want: VfsId) -> bool {
    entries
        .iter()
        .any(|e| e.state == SS_LISTEN && e.vfs == Some(want))
}

// ---------------------------------------------------------------------------
// The live half
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod live {
    use std::io;
    use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
    use std::time::Duration;

    use crate::platform::linux::clock::Deadline;

    use super::{
        Entry, NLM_F_REQUEST_DUMP, SOCK_DIAG_BY_FAMILY, UDIAG_SHOW_VFS, VfsId, has_listener_for,
        parse_dump,
    };

    /// A `NETLINK_SOCK_DIAG` socket, bound to the network namespace it was
    /// created in.
    ///
    /// The mediator uses one opened by the trusted launcher **inside the
    /// attempt's netns** (handed over by `pidfd_getfd`); a socket keeps the
    /// netns it was created in, so a dump on it enumerates exactly the attempt's
    /// sockets even when the caller is the supervisor in the host netns.
    pub struct SockDiag {
        fd: OwnedFd,
        seq: u32,
    }

    impl SockDiag {
        /// Open a fresh `NETLINK_SOCK_DIAG` socket in the caller's netns.
        ///
        /// Used by [`super::super::unixpeer::launcher_setup`] inside the
        /// launcher; the supervisor never opens one itself, it takes the
        /// launcher's.
        ///
        /// # Errors
        ///
        /// The errno of `socket`.
        pub fn open() -> io::Result<Self> {
            // SAFETY: socket() with a constant family/type/protocol and no
            // pointer arguments; the returned fd is owned here.
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    libc::NETLINK_SOCK_DIAG,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` was just created and is owned here.
            Ok(Self {
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
                seq: 0,
            })
        }

        /// Adopt an already-open `NETLINK_SOCK_DIAG` fd (the one taken from the
        /// launcher's netns).
        #[must_use]
        pub fn from_fd(fd: OwnedFd) -> Self {
            Self { fd, seq: 0 }
        }

        /// The raw fd, for lifetime management by the owner.
        #[must_use]
        pub fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }

        /// Take back the owned fd (the launcher keeps it alive as a guard until
        /// the supervisor has taken it with `pidfd_getfd`).
        #[must_use]
        pub fn into_owned(self) -> OwnedFd {
            self.fd
        }

        /// Dump every AF_UNIX socket in this socket's netns, requesting `show`.
        /// A readable `stop` ends the dump early with `Interrupted`; with
        /// none, the dump's own deadline and datagram bound still apply.
        ///
        /// # Errors
        ///
        /// A send/recv failure, or a malformed dump (see [`parse_dump`]).
        pub fn dump(&mut self, show: u32, stop: Option<BorrowedFd<'_>>) -> io::Result<Vec<Entry>> {
            let deadline = Deadline::after(Duration::from_secs(2));
            self.seq = self.seq.wrapping_add(1);
            let seq = self.seq;
            self.send_request(seq, show)?;
            let mut out = Vec::new();
            let mut buf = vec![0u8; 32 * 1024];
            // One deadline covers the entire dump, including a peer which
            // keeps sending datagrams. Stop wakes the poll immediately.
            const MAX_DATAGRAMS: usize = 4096;
            let mut datagrams = 0usize;
            loop {
                if deadline.expired() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "sock_diag: dump timed out",
                    ));
                }
                datagrams += 1;
                if datagrams > MAX_DATAGRAMS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sock_diag: dump exceeded the datagram bound",
                    ));
                }
                let mut pfds = [
                    libc::pollfd {
                        fd: self.fd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        // poll ignores a negative descriptor.
                        fd: stop.map_or(-1, |stop| stop.as_raw_fd()),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                // SAFETY: two live pollfds.
                let p = unsafe {
                    libc::poll(pfds.as_mut_ptr(), 2, deadline.remaining_millis_capped(2000))
                };
                if p == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "sock_diag: dump timed out",
                    ));
                }
                if p < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(err);
                }
                if pfds[1].revents != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "sock_diag: mediator stopping",
                    ));
                }
                if pfds[0].revents & libc::POLLIN == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "sock_diag: socket unavailable",
                    ));
                }
                // SAFETY: `buf` is a live, writable slice of `buf.len()` bytes.
                let n = unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if matches!(
                        err.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) {
                        continue;
                    }
                    return Err(err);
                }
                if parse_dump(&buf[..n as usize], seq, &mut out)? {
                    return Ok(out);
                }
            }
        }

        /// Whether a *listening* socket bound to `want`'s filesystem identity
        /// exists in this netns.
        ///
        /// # Errors
        ///
        /// As [`SockDiag::dump`].
        pub fn has_listener_for(&mut self, want: VfsId, stop: BorrowedFd<'_>) -> io::Result<bool> {
            let entries = self.dump(UDIAG_SHOW_VFS, Some(stop))?;
            Ok(has_listener_for(&entries, want))
        }

        fn send_request(&self, seq: u32, show: u32) -> io::Result<()> {
            // nlmsghdr (16) + unix_diag_req (24).
            let mut req = [0u8; 40];
            req[0..4].copy_from_slice(&40u32.to_ne_bytes());
            req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
            req[6..8].copy_from_slice(&NLM_F_REQUEST_DUMP.to_ne_bytes());
            req[8..12].copy_from_slice(&seq.to_ne_bytes());
            // unix_diag_req { sdiag_family; sdiag_protocol; pad; states; ino;
            //                 show; cookie[2]; }
            req[16] = u8::try_from(libc::AF_UNIX).unwrap_or(1);
            req[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // all states
            req[28..32].copy_from_slice(&show.to_ne_bytes());
            req[32..40].copy_from_slice(&(-1i64).to_ne_bytes()); // INET_DIAG_NOCOOKIE

            let mut nl: libc::sockaddr_nl = zeroed_sockaddr_nl();
            nl.nl_family = u16::try_from(libc::AF_NETLINK).unwrap_or(16);
            // SAFETY: `req` is a live 40-byte buffer; `nl` is a live
            // `sockaddr_nl` whose length is passed correctly. sendto copies both
            // and returns before either is dropped.
            let rc = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    req.as_ptr().cast::<libc::c_void>(),
                    req.len(),
                    libc::MSG_DONTWAIT,
                    std::ptr::from_ref(&nl).cast::<libc::sockaddr>(),
                    u32::try_from(std::mem::size_of::<libc::sockaddr_nl>()).unwrap(),
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    fn zeroed_sockaddr_nl() -> libc::sockaddr_nl {
        // SAFETY: `sockaddr_nl` is a plain-old-data struct of integers with no
        // invariant that all-zero violates; the fields set by the caller are
        // written before use.
        unsafe { std::mem::zeroed() }
    }
}

#[cfg(target_os = "linux")]
pub use live::SockDiag;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn a_signaled_stop_interrupts_a_sock_diag_dump() {
        use std::io::Write as _;
        use std::os::fd::AsFd as _;
        let (read, write) = crate::platform::linux::exec::pipe().expect("pipe");
        std::fs::File::from(write)
            .write_all(b"x")
            .expect("stop byte");
        let mut diag = SockDiag::open().expect("sock_diag socket");
        let error = diag
            .dump(UDIAG_SHOW_VFS, Some(read.as_fd()))
            .expect_err("stop must interrupt dump");
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }

    /// Build one `SOCK_DIAG_BY_FAMILY` message with an optional VFS attribute.
    fn unix_msg(seq: u32, state: u8, sock_ino: u32, vfs: Option<(u32, u32)>) -> Vec<u8> {
        let mut body = vec![0u8; 16];
        body[0] = 1; // AF_UNIX
        body[1] = 1; // SOCK_STREAM
        body[2] = state;
        body[4..8].copy_from_slice(&sock_ino.to_ne_bytes());
        if let Some((ino, dev)) = vfs {
            // attr: len(4) + type(2) + payload(8) = 12, padded to 12
            let mut attr = Vec::new();
            attr.extend_from_slice(&12u16.to_ne_bytes());
            attr.extend_from_slice(&UNIX_DIAG_VFS.to_ne_bytes());
            attr.extend_from_slice(&ino.to_ne_bytes());
            attr.extend_from_slice(&dev.to_ne_bytes());
            body.extend_from_slice(&attr);
        }
        let total = 16 + body.len();
        let mut msg = Vec::new();
        msg.extend_from_slice(&u32::try_from(total).unwrap().to_ne_bytes());
        msg.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
        msg.extend_from_slice(&body);
        while msg.len() % 4 != 0 {
            msg.push(0);
        }
        msg
    }

    fn done(seq: u32) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&16u32.to_ne_bytes());
        msg.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg
    }

    #[test]
    fn a_listening_socket_with_a_matching_vfs_is_found() {
        let mut buf = unix_msg(7, SS_LISTEN, 100, Some((2534, 8_388_609)));
        buf.extend(done(7));
        let mut out = Vec::new();
        assert!(parse_dump(&buf, 7, &mut out).unwrap());
        assert_eq!(out.len(), 1);
        assert!(has_listener_for(
            &out,
            VfsId {
                ino: 2534,
                dev: 8_388_609
            }
        ));
    }

    #[test]
    fn a_non_listening_socket_is_not_a_match() {
        let mut buf = unix_msg(1, 1 /* SS_ESTABLISHED */, 100, Some((2534, 8_388_609)));
        buf.extend(done(1));
        let mut out = Vec::new();
        parse_dump(&buf, 1, &mut out).unwrap();
        assert!(!has_listener_for(
            &out,
            VfsId {
                ino: 2534,
                dev: 8_388_609
            }
        ));
    }

    #[test]
    fn a_different_inode_is_not_a_match() {
        let mut buf = unix_msg(1, SS_LISTEN, 100, Some((2534, 8_388_609)));
        buf.extend(done(1));
        let mut out = Vec::new();
        parse_dump(&buf, 1, &mut out).unwrap();
        assert!(!has_listener_for(
            &out,
            VfsId {
                ino: 9999,
                dev: 8_388_609
            }
        ));
    }

    #[test]
    fn a_sequence_mismatch_is_an_error_not_an_empty_result() {
        let buf = unix_msg(7, SS_LISTEN, 100, Some((2534, 8_388_609)));
        let mut out = Vec::new();
        assert!(parse_dump(&buf, 8, &mut out).is_err());
    }

    #[test]
    fn a_truncated_message_is_an_error() {
        let mut buf = unix_msg(1, SS_LISTEN, 100, None);
        buf.truncate(buf.len() - 3);
        // The header still claims the full length, so parsing must reject it.
        let mut out = Vec::new();
        assert!(parse_dump(&buf, 1, &mut out).is_err());
    }

    #[test]
    fn an_nlmsg_error_is_surfaced() {
        let mut msg = Vec::new();
        msg.extend_from_slice(&20u32.to_ne_bytes());
        msg.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&3u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&(-libc::EACCES).to_ne_bytes());
        let mut out = Vec::new();
        let err = parse_dump(&msg, 3, &mut out).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn a_short_nlmsg_error_is_rejected_without_panicking() {
        let mut msg = Vec::new();
        msg.extend_from_slice(&16u32.to_ne_bytes());
        msg.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&3u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        let err = parse_dump(&msg, 3, &mut Vec::new()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_truncated_attribute_or_header_is_rejected_without_panicking() {
        // An attribute whose length runs past the message.
        let mut buf = unix_msg(1, SS_LISTEN, 100, Some((2534, 8_388_609)));
        let attribute = 16 + UNIX_DIAG_MSG_LEN;
        buf[attribute..attribute + 2].copy_from_slice(&64u16.to_ne_bytes());
        assert_eq!(
            parse_dump(&buf, 1, &mut Vec::new()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // A message header that claims less than a header.
        let mut buf = done(1);
        buf[0..4].copy_from_slice(&8u32.to_ne_bytes());
        assert_eq!(
            parse_dump(&buf, 1, &mut Vec::new()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // A partial header is not a message yet: read more.
        assert!(!parse_dump(&done(1)[..12], 1, &mut Vec::new()).unwrap());
    }

    #[test]
    fn an_inode_beyond_u32_cannot_form_a_vfs_identity() {
        // The refusal that keeps a wide-inode filesystem from being mistaken for
        // a matching node (spike §3a).
        assert!(VfsId::from_stat(u64::from(u32::MAX) + 1, 2049).is_none());
        assert!(VfsId::from_stat(42, 2049).is_some());
    }

    #[test]
    fn device_encoding_matches_the_kernel_form() {
        // ext4 root on the reference host: st_dev 2049 -> major 8 minor 1 ->
        // kernel dev 8<<20 | 1 = 8388609 (observed in the spike).
        assert_eq!(VfsId::encode_dev(2049), 8_388_609);
        assert_eq!(dev_major(2049), 8);
        assert_eq!(dev_minor(2049), 1);
        // A tmpfs dev on the reference host: st_dev 44 -> major 0 minor 44.
        assert_eq!(VfsId::encode_dev(44), 44);
    }
}
