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
//! hand-built buffer; only [`SockDiag::listeners`] and [`SockDiag::open`] call
//! the kernel.

use std::io;

/// `SOCK_DIAG_BY_FAMILY`.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// `NLMSG_ERROR`.
const NLMSG_ERROR: u16 = 2;
/// `NLMSG_DONE`.
const NLMSG_DONE: u16 = 3;
/// `NLM_F_REQUEST | NLM_F_DUMP`.
const NLM_F_REQUEST_DUMP: u16 = 0x0001 | 0x0300;
/// `UNIX_DIAG_NAME` attribute type.
const UNIX_DIAG_NAME: u16 = 0;
/// `UNIX_DIAG_VFS` attribute type.
const UNIX_DIAG_VFS: u16 = 1;

/// `UDIAG_SHOW_NAME`: request the bound name attribute.
pub const UDIAG_SHOW_NAME: u32 = 0x0000_0001;
/// `UDIAG_SHOW_VFS`: request the on-disk inode/dev of a pathname socket.
pub const UDIAG_SHOW_VFS: u32 = 0x0000_0002;

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

/// One socket from a unix `sock_diag` dump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The socket's own inode (`udiag_ino`), not the on-disk node.
    pub sock_ino: u32,
    /// `SOCK_STREAM`, `SOCK_DGRAM` or `SOCK_SEQPACKET`.
    pub sock_type: u8,
    /// The TCP-style state; [`SS_LISTEN`] for a listening socket.
    pub state: u8,
    /// `UNIX_DIAG_VFS`, present only for a *bound pathname* socket and only
    /// when `UDIAG_SHOW_VFS` was requested.
    pub vfs: Option<VfsId>,
    /// `UNIX_DIAG_NAME`, the bound name (a leading NUL marks an abstract name).
    pub name: Option<Vec<u8>>,
}

/// Parse a sequence of received netlink bytes into unix `sock_diag` entries.
///
/// Pure: it performs no I/O and is the unit under test. It rejects a truncated
/// message, an attribute that runs past its message, a sequence mismatch and a
/// `NLMSG_ERROR`, rather than skipping quietly — a short read must not look
/// like "no such listener".
///
/// Returns `Ok(None)` when the buffer did not contain the `NLMSG_DONE` marker
/// (the caller must read more), or `Ok(Some(entries))` when the dump ended.
///
/// # Errors
///
/// [`io::Error`] for a malformed message, a sequence mismatch, or the errno of
/// a `NLMSG_ERROR` reply.
pub fn parse_dump(buf: &[u8], expect_seq: u32, out: &mut Vec<Entry>) -> io::Result<bool> {
    let mut off = 0usize;
    while off + 16 <= buf.len() {
        let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
        let seq = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
        if len < 16 || off + len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sock_diag: truncated netlink message",
            ));
        }
        if seq != expect_seq {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sock_diag: sequence mismatch",
            ));
        }
        match ty {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let err = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                if err == 0 {
                    return Ok(true); // an ACK, treated as a clean end
                }
                return Err(io::Error::from_raw_os_error(-err));
            }
            SOCK_DIAG_BY_FAMILY => {
                out.push(parse_unix_msg(&buf[off + 16..off + len])?);
            }
            _ => {}
        }
        off += (len + 3) & !3;
    }
    Ok(false)
}

/// Parse one `unix_diag_msg` and its attributes.
fn parse_unix_msg(body: &[u8]) -> io::Result<Entry> {
    // struct unix_diag_msg { u8 family; u8 type; u8 state; u8 pad; u32 ino;
    //                        u32 cookie[2]; } then netlink attributes.
    if body.len() < 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sock_diag: short unix_diag_msg",
        ));
    }
    let mut entry = Entry {
        sock_type: body[1],
        state: body[2],
        sock_ino: u32::from_ne_bytes(body[4..8].try_into().unwrap()),
        vfs: None,
        name: None,
    };
    let mut a = 16usize;
    while a + 4 <= body.len() {
        let alen = u16::from_ne_bytes(body[a..a + 2].try_into().unwrap()) as usize;
        let aty = u16::from_ne_bytes(body[a + 2..a + 4].try_into().unwrap()) & 0x3fff;
        if alen < 4 || a + alen > body.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sock_diag: attribute runs past its message",
            ));
        }
        let payload = &body[a + 4..a + alen];
        if aty == UNIX_DIAG_VFS && payload.len() >= 8 {
            entry.vfs = Some(VfsId {
                ino: u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
                dev: u32::from_ne_bytes(payload[4..8].try_into().unwrap()),
            });
        } else if aty == UNIX_DIAG_NAME {
            entry.name = Some(payload.to_vec());
        }
        a += (alen + 3) & !3;
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
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

    use super::{
        Entry, NLM_F_REQUEST_DUMP, SOCK_DIAG_BY_FAMILY, VfsId, has_listener_for, parse_dump,
    };

    /// `NETLINK_SOCK_DIAG`.
    const NETLINK_SOCK_DIAG: libc::c_int = 4;

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
                    NETLINK_SOCK_DIAG,
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
        ///
        /// # Errors
        ///
        /// A send/recv failure, or a malformed dump (see [`parse_dump`]).
        pub fn dump(&mut self, show: u32) -> io::Result<Vec<Entry>> {
            self.seq = self.seq.wrapping_add(1);
            let seq = self.seq;
            self.send_request(seq, show)?;
            let mut out = Vec::new();
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                // SAFETY: `buf` is a live, writable slice of `buf.len()` bytes.
                let n = unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                        0,
                    )
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
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
        pub fn has_listener_for(&mut self, want: VfsId) -> io::Result<bool> {
            let entries = self.dump(super::UDIAG_SHOW_VFS | super::UDIAG_SHOW_NAME)?;
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
                    0,
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
