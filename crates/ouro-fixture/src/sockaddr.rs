//! Socket addresses whose length can never exceed their storage.
//!
//! `bind`, `connect` and `sendto` take a pointer and a length, and the kernel
//! reads that many bytes. A length computed from a caller's path is how a
//! `sockaddr_un` overruns: a path longer than `sun_path` would either be cut
//! (and name a different socket) or be read past the structure. [`SockAddr`]
//! is the unsafe boundary: every constructor checks the bytes against the real
//! `sun_path` capacity of this platform first and refuses, before any
//! syscall, what does not fit. `tests/unix_modes.rs` tries to violate it.

use std::net::SocketAddr;

use crate::cli::UnixLen;

/// An address that could not be built. The reason goes on the report line.
#[derive(Debug, PartialEq, Eq)]
pub struct AddrRefused {
    pub reason: &'static str,
}

enum Storage {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
    Unix(libc::sockaddr_un),
}

/// A live socket address and the exact length to pass with it.
pub struct SockAddr {
    storage: Storage,
    len: libc::socklen_t,
}

impl std::fmt::Debug for SockAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SockAddr")
            .field("family", &self.family_name())
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// `offsetof(struct sockaddr_un, sun_path)`.
#[must_use]
pub const fn sun_path_offset() -> usize {
    std::mem::offset_of!(libc::sockaddr_un, sun_path)
}

/// Bytes available in `sun_path` here: 108 on Linux, 104 on Darwin.
#[must_use]
pub const fn sun_path_capacity() -> usize {
    size_of::<libc::sockaddr_un>() - sun_path_offset()
}

fn zeroed_un() -> libc::sockaddr_un {
    // SAFETY: `sockaddr_un` is plain old data; all-zero bytes are a valid
    // value (family 0, empty path).
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    sa
}

impl SockAddr {
    /// A numeric IPv4 or IPv6 address.
    #[must_use]
    pub fn inet(addr: SocketAddr) -> SockAddr {
        match addr {
            SocketAddr::V4(v4) => {
                // SAFETY: `sockaddr_in` is plain old data; zero is valid.
                let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_port = v4.port().to_be();
                sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                #[cfg(not(target_os = "linux"))]
                {
                    sa.sin_len = size_of::<libc::sockaddr_in>() as u8;
                }
                SockAddr {
                    storage: Storage::V4(sa),
                    len: size_of::<libc::sockaddr_in>() as libc::socklen_t,
                }
            }
            SocketAddr::V6(v6) => {
                // SAFETY: `sockaddr_in6` is plain old data; zero is valid.
                let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_port = v6.port().to_be();
                sa.sin6_addr.s6_addr = v6.ip().octets();
                sa.sin6_scope_id = v6.scope_id();
                sa.sin6_flowinfo = v6.flowinfo();
                #[cfg(not(target_os = "linux"))]
                {
                    sa.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
                }
                SockAddr {
                    storage: Storage::V6(sa),
                    len: size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                }
            }
        }
    }

    /// A pathname AF_UNIX address, passed with the length variant `len`.
    ///
    /// Refused before any syscall: an empty path (with `nul` it would become
    /// the empty *abstract* name), an interior NUL (the kernel would see a
    /// shorter path), and a path that does not fit `sun_path` with the bytes
    /// the variant needs.
    pub fn unix_path(path: &[u8], variant: UnixLen) -> Result<SockAddr, AddrRefused> {
        if path.is_empty() {
            return Err(AddrRefused {
                reason: "empty_path",
            });
        }
        if path.contains(&0) {
            return Err(AddrRefused {
                reason: "interior_nul",
            });
        }
        let needed = match variant {
            UnixLen::Exact | UnixLen::Full => path.len(),
            UnixLen::Nul => path.len() + 1,
        };
        if needed > sun_path_capacity() {
            return Err(AddrRefused {
                reason: "path_too_long",
            });
        }
        let mut sa = zeroed_un();
        for (dst, src) in sa.sun_path.iter_mut().zip(path) {
            *dst = *src as libc::c_char;
        }
        let len = match variant {
            UnixLen::Exact => sun_path_offset() + path.len(),
            UnixLen::Nul => sun_path_offset() + path.len() + 1,
            UnixLen::Full => size_of::<libc::sockaddr_un>(),
        };
        #[cfg(not(target_os = "linux"))]
        {
            sa.sun_len = len as u8;
        }
        Ok(SockAddr {
            storage: Storage::Unix(sa),
            len: len as libc::socklen_t,
        })
    }

    /// An abstract AF_UNIX address: a NUL, then NAME, length-delimited. Only
    /// Linux gives these a meaning; the caller refuses elsewhere.
    pub fn unix_abstract(name: &[u8]) -> Result<SockAddr, AddrRefused> {
        if name.len() + 1 > sun_path_capacity() {
            return Err(AddrRefused {
                reason: "name_too_long",
            });
        }
        let mut sa = zeroed_un();
        for (dst, src) in sa.sun_path.iter_mut().skip(1).zip(name) {
            *dst = *src as libc::c_char;
        }
        let len = sun_path_offset() + 1 + name.len();
        #[cfg(not(target_os = "linux"))]
        {
            sa.sun_len = len as u8;
        }
        Ok(SockAddr {
            storage: Storage::Unix(sa),
            len: len as libc::socklen_t,
        })
    }

    /// The address for the kernel. Valid for as long as `self` is borrowed.
    #[must_use]
    pub fn as_ptr(&self) -> *const libc::sockaddr {
        match &self.storage {
            Storage::V4(sa) => std::ptr::from_ref(sa).cast(),
            Storage::V6(sa) => std::ptr::from_ref(sa).cast(),
            Storage::Unix(sa) => std::ptr::from_ref(sa).cast(),
        }
    }

    /// The `addrlen` to pass. Never more than [`SockAddr::storage_size`].
    #[must_use]
    pub fn len(&self) -> libc::socklen_t {
        self.len
    }

    /// Never true: every constructor produces at least a family.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes of live storage behind [`SockAddr::as_ptr`].
    #[must_use]
    pub fn storage_size(&self) -> usize {
        match &self.storage {
            Storage::V4(_) => size_of::<libc::sockaddr_in>(),
            Storage::V6(_) => size_of::<libc::sockaddr_in6>(),
            Storage::Unix(_) => size_of::<libc::sockaddr_un>(),
        }
    }

    /// `AF_INET`, `AF_INET6` or `AF_UNIX`, for the report line.
    #[must_use]
    pub fn family_name(&self) -> &'static str {
        match &self.storage {
            Storage::V4(_) => "AF_INET",
            Storage::V6(_) => "AF_INET6",
            Storage::Unix(_) => "AF_UNIX",
        }
    }

    /// The `domain` argument for `socket`.
    #[must_use]
    pub fn domain(&self) -> libc::c_int {
        match &self.storage {
            Storage::V4(_) => libc::AF_INET,
            Storage::V6(_) => libc::AF_INET6,
            Storage::Unix(_) => libc::AF_UNIX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capacity_is_the_real_sun_path_size() {
        #[cfg(target_os = "linux")]
        assert_eq!(sun_path_capacity(), 108);
        #[cfg(target_os = "macos")]
        assert_eq!(sun_path_capacity(), 104);
        assert_eq!(
            sun_path_capacity(),
            zeroed_un().sun_path.len(),
            "offset arithmetic and the field agree"
        );
    }

    #[test]
    fn each_length_variant_passes_what_it_names() {
        let p = b"/tmp/s";
        let exact = SockAddr::unix_path(p, UnixLen::Exact).unwrap();
        let nul = SockAddr::unix_path(p, UnixLen::Nul).unwrap();
        let full = SockAddr::unix_path(p, UnixLen::Full).unwrap();
        assert_eq!(exact.len() as usize, sun_path_offset() + p.len());
        assert_eq!(nul.len() as usize, sun_path_offset() + p.len() + 1);
        assert_eq!(full.len() as usize, size_of::<libc::sockaddr_un>());
        for a in [&exact, &nul, &full] {
            assert!(a.len() as usize <= a.storage_size());
            assert_eq!(a.family_name(), "AF_UNIX");
        }
    }

    #[test]
    fn a_path_that_does_not_fit_is_refused_not_cut() {
        // The precondition of every unsafe call that takes a `SockAddr`: the
        // length never exceeds the storage. Try to break it at the edges.
        let cap = sun_path_capacity();
        let fits_exact = vec![b'a'; cap];
        assert!(SockAddr::unix_path(&fits_exact, UnixLen::Exact).is_ok());
        assert!(SockAddr::unix_path(&fits_exact, UnixLen::Full).is_ok());
        assert_eq!(
            SockAddr::unix_path(&fits_exact, UnixLen::Nul).unwrap_err(),
            AddrRefused {
                reason: "path_too_long"
            },
            "the NUL variant needs one more byte"
        );
        let too_long = vec![b'a'; cap + 1];
        for v in [UnixLen::Exact, UnixLen::Nul, UnixLen::Full] {
            assert_eq!(
                SockAddr::unix_path(&too_long, v).unwrap_err().reason,
                "path_too_long"
            );
        }
        let huge = vec![b'a'; 4096];
        assert!(SockAddr::unix_path(&huge, UnixLen::Exact).is_err());
    }

    #[test]
    fn an_empty_or_nul_bearing_path_is_refused() {
        assert_eq!(
            SockAddr::unix_path(b"", UnixLen::Nul).unwrap_err().reason,
            "empty_path"
        );
        assert_eq!(
            SockAddr::unix_path(b"/tmp/a\0b", UnixLen::Exact)
                .unwrap_err()
                .reason,
            "interior_nul"
        );
    }

    #[test]
    fn an_abstract_name_is_length_delimited_and_bounded() {
        let a = SockAddr::unix_abstract(b"ouro").unwrap();
        assert_eq!(a.len() as usize, sun_path_offset() + 1 + 4);
        let max = vec![b'x'; sun_path_capacity() - 1];
        let m = SockAddr::unix_abstract(&max).unwrap();
        assert_eq!(m.len() as usize, size_of::<libc::sockaddr_un>());
        assert!(m.len() as usize <= m.storage_size());
        let over = vec![b'x'; sun_path_capacity()];
        assert_eq!(
            SockAddr::unix_abstract(&over).unwrap_err().reason,
            "name_too_long"
        );
    }

    #[test]
    fn inet_addresses_carry_their_own_sizes() {
        let v4 = SockAddr::inet("127.0.0.1:80".parse().unwrap());
        assert_eq!(v4.len() as usize, size_of::<libc::sockaddr_in>());
        assert_eq!(v4.domain(), libc::AF_INET);
        let v6 = SockAddr::inet("[::1]:80".parse().unwrap());
        assert_eq!(v6.len() as usize, size_of::<libc::sockaddr_in6>());
        assert_eq!(v6.family_name(), "AF_INET6");
        assert!(!v6.is_empty());
    }
}
