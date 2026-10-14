//! Small shared helpers for the Linux platform modules.

use std::ffi::{CString, OsStr};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// A path or argument that cannot be passed to a syscall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathError {
    /// The bytes contain a NUL, so the kernel would see a truncated string.
    /// Refused before the syscall rather than silently shortened.
    InteriorNul {
        /// Byte offset of the first NUL.
        offset: usize,
    },
    /// The path is empty.
    Empty,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul { offset } => {
                write!(f, "path contains a NUL byte at offset {offset}")
            }
            Self::Empty => write!(f, "path is empty"),
        }
    }
}

impl std::error::Error for PathError {}

/// Convert an `OsStr` to a `CString`, refusing an interior NUL.
///
/// # Errors
///
/// [`PathError::InteriorNul`] when the bytes contain a NUL.
pub fn cstring_from_os(value: &OsStr) -> Result<CString, PathError> {
    let bytes = value.as_bytes();
    if let Some(offset) = bytes.iter().position(|b| *b == 0) {
        return Err(PathError::InteriorNul { offset });
    }
    Ok(CString::new(bytes).expect("checked for NUL above"))
}

/// Convert a path to a `CString`, refusing an empty path or an interior NUL.
///
/// # Errors
///
/// [`PathError::Empty`] or [`PathError::InteriorNul`].
pub fn cstring_from_path(path: &Path) -> Result<CString, PathError> {
    if path.as_os_str().is_empty() {
        return Err(PathError::Empty);
    }
    cstring_from_os(path.as_os_str())
}

/// An all-zero `libc::stat`, to be filled in by a `stat`, `lstat` or `fstat`
/// call. Callers must check that call's return value before reading a field.
#[must_use]
pub fn empty_stat() -> libc::stat {
    // SAFETY: `libc::stat` is a plain C struct of integers and has no
    // invariant that all-zero violates; it is a scratch buffer here, and the
    // kernel overwrites it on a successful call.
    unsafe { std::mem::zeroed() }
}

/// The errno of the most recent failing syscall on this thread.
#[must_use]
pub fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

// An inherited ignored disposition is the operator's
/// Whether `signal` is ignored in this process right now, read without
/// changing it. A read that fails says "not ignored".
#[must_use]
pub fn signal_ignored(signal: libc::c_int) -> bool {
    // SAFETY: a null new action only reads the current one into `current`,
    // which is plain data this frame owns.
    unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        libc::sigaction(signal, std::ptr::null(), &raw mut current) == 0
            && current.sa_sigaction == libc::SIG_IGN
    }
}

/// The jail's own pipes carry their integers little-endian: a launcher's
/// errno report (and its detail code), the bootstrap's exec handshake and
/// the narrowing trace data. One definition, so writer and reader agree by
/// construction rather than by running on the same host. `const` and
/// allocation-free, for code that runs after a fork or under the narrowing
/// filter.
#[must_use]
pub const fn errno_bytes(errno: i32) -> [u8; 4] {
    errno.to_le_bytes()
}

/// The errno [`errno_bytes`] wrote.
#[must_use]
pub const fn errno_from_bytes(bytes: [u8; 4]) -> i32 {
    i32::from_le_bytes(bytes)
}

/// The narrowing filter's 16-bit trace data in the [`errno_bytes`] order.
#[must_use]
pub const fn trace_data_bytes(data: u16) -> [u8; 2] {
    data.to_le_bytes()
}

/// The trace data [`trace_data_bytes`] wrote.
#[must_use]
pub const fn trace_data_from_bytes(bytes: [u8; 2]) -> u16 {
    u16::from_le_bytes(bytes)
}

/// Every errno Linux defines, by its symbolic name, in number order (the
/// asm-generic numbering x86_64 and aarch64 share). Aliases (`EWOULDBLOCK`,
/// `EDEADLOCK`, `ENOTSUP`) name a number already here and are left out.
const ERRNOS: &[(i32, &str)] = &[
    (libc::EPERM, "EPERM"),
    (libc::ENOENT, "ENOENT"),
    (libc::ESRCH, "ESRCH"),
    (libc::EINTR, "EINTR"),
    (libc::EIO, "EIO"),
    (libc::ENXIO, "ENXIO"),
    (libc::E2BIG, "E2BIG"),
    (libc::ENOEXEC, "ENOEXEC"),
    (libc::EBADF, "EBADF"),
    (libc::ECHILD, "ECHILD"),
    (libc::EAGAIN, "EAGAIN"),
    (libc::ENOMEM, "ENOMEM"),
    (libc::EACCES, "EACCES"),
    (libc::EFAULT, "EFAULT"),
    (libc::ENOTBLK, "ENOTBLK"),
    (libc::EBUSY, "EBUSY"),
    (libc::EEXIST, "EEXIST"),
    (libc::EXDEV, "EXDEV"),
    (libc::ENODEV, "ENODEV"),
    (libc::ENOTDIR, "ENOTDIR"),
    (libc::EISDIR, "EISDIR"),
    (libc::EINVAL, "EINVAL"),
    (libc::ENFILE, "ENFILE"),
    (libc::EMFILE, "EMFILE"),
    (libc::ENOTTY, "ENOTTY"),
    (libc::ETXTBSY, "ETXTBSY"),
    (libc::EFBIG, "EFBIG"),
    (libc::ENOSPC, "ENOSPC"),
    (libc::ESPIPE, "ESPIPE"),
    (libc::EROFS, "EROFS"),
    (libc::EMLINK, "EMLINK"),
    (libc::EPIPE, "EPIPE"),
    (libc::EDOM, "EDOM"),
    (libc::ERANGE, "ERANGE"),
    (libc::EDEADLK, "EDEADLK"),
    (libc::ENAMETOOLONG, "ENAMETOOLONG"),
    (libc::ENOLCK, "ENOLCK"),
    (libc::ENOSYS, "ENOSYS"),
    (libc::ENOTEMPTY, "ENOTEMPTY"),
    (libc::ELOOP, "ELOOP"),
    (libc::ENOMSG, "ENOMSG"),
    (libc::EIDRM, "EIDRM"),
    (libc::ECHRNG, "ECHRNG"),
    (libc::EL2NSYNC, "EL2NSYNC"),
    (libc::EL3HLT, "EL3HLT"),
    (libc::EL3RST, "EL3RST"),
    (libc::ELNRNG, "ELNRNG"),
    (libc::EUNATCH, "EUNATCH"),
    (libc::ENOCSI, "ENOCSI"),
    (libc::EL2HLT, "EL2HLT"),
    (libc::EBADE, "EBADE"),
    (libc::EBADR, "EBADR"),
    (libc::EXFULL, "EXFULL"),
    (libc::ENOANO, "ENOANO"),
    (libc::EBADRQC, "EBADRQC"),
    (libc::EBADSLT, "EBADSLT"),
    (libc::EBFONT, "EBFONT"),
    (libc::ENOSTR, "ENOSTR"),
    (libc::ENODATA, "ENODATA"),
    (libc::ETIME, "ETIME"),
    (libc::ENOSR, "ENOSR"),
    (libc::ENONET, "ENONET"),
    (libc::ENOPKG, "ENOPKG"),
    (libc::EREMOTE, "EREMOTE"),
    (libc::ENOLINK, "ENOLINK"),
    (libc::EADV, "EADV"),
    (libc::ESRMNT, "ESRMNT"),
    (libc::ECOMM, "ECOMM"),
    (libc::EPROTO, "EPROTO"),
    (libc::EMULTIHOP, "EMULTIHOP"),
    (libc::EDOTDOT, "EDOTDOT"),
    (libc::EBADMSG, "EBADMSG"),
    (libc::EOVERFLOW, "EOVERFLOW"),
    (libc::ENOTUNIQ, "ENOTUNIQ"),
    (libc::EBADFD, "EBADFD"),
    (libc::EREMCHG, "EREMCHG"),
    (libc::ELIBACC, "ELIBACC"),
    (libc::ELIBBAD, "ELIBBAD"),
    (libc::ELIBSCN, "ELIBSCN"),
    (libc::ELIBMAX, "ELIBMAX"),
    (libc::ELIBEXEC, "ELIBEXEC"),
    (libc::EILSEQ, "EILSEQ"),
    (libc::ERESTART, "ERESTART"),
    (libc::ESTRPIPE, "ESTRPIPE"),
    (libc::EUSERS, "EUSERS"),
    (libc::ENOTSOCK, "ENOTSOCK"),
    (libc::EDESTADDRREQ, "EDESTADDRREQ"),
    (libc::EMSGSIZE, "EMSGSIZE"),
    (libc::EPROTOTYPE, "EPROTOTYPE"),
    (libc::ENOPROTOOPT, "ENOPROTOOPT"),
    (libc::EPROTONOSUPPORT, "EPROTONOSUPPORT"),
    (libc::ESOCKTNOSUPPORT, "ESOCKTNOSUPPORT"),
    (libc::EOPNOTSUPP, "EOPNOTSUPP"),
    (libc::EPFNOSUPPORT, "EPFNOSUPPORT"),
    (libc::EAFNOSUPPORT, "EAFNOSUPPORT"),
    (libc::EADDRINUSE, "EADDRINUSE"),
    (libc::EADDRNOTAVAIL, "EADDRNOTAVAIL"),
    (libc::ENETDOWN, "ENETDOWN"),
    (libc::ENETUNREACH, "ENETUNREACH"),
    (libc::ENETRESET, "ENETRESET"),
    (libc::ECONNABORTED, "ECONNABORTED"),
    (libc::ECONNRESET, "ECONNRESET"),
    (libc::ENOBUFS, "ENOBUFS"),
    (libc::EISCONN, "EISCONN"),
    (libc::ENOTCONN, "ENOTCONN"),
    (libc::ESHUTDOWN, "ESHUTDOWN"),
    (libc::ETOOMANYREFS, "ETOOMANYREFS"),
    (libc::ETIMEDOUT, "ETIMEDOUT"),
    (libc::ECONNREFUSED, "ECONNREFUSED"),
    (libc::EHOSTDOWN, "EHOSTDOWN"),
    (libc::EHOSTUNREACH, "EHOSTUNREACH"),
    (libc::EALREADY, "EALREADY"),
    (libc::EINPROGRESS, "EINPROGRESS"),
    (libc::ESTALE, "ESTALE"),
    (libc::EUCLEAN, "EUCLEAN"),
    (libc::ENOTNAM, "ENOTNAM"),
    (libc::ENAVAIL, "ENAVAIL"),
    (libc::EISNAM, "EISNAM"),
    (libc::EREMOTEIO, "EREMOTEIO"),
    (libc::EDQUOT, "EDQUOT"),
    (libc::ENOMEDIUM, "ENOMEDIUM"),
    (libc::EMEDIUMTYPE, "EMEDIUMTYPE"),
    (libc::ECANCELED, "ECANCELED"),
    (libc::ENOKEY, "ENOKEY"),
    (libc::EKEYEXPIRED, "EKEYEXPIRED"),
    (libc::EKEYREVOKED, "EKEYREVOKED"),
    (libc::EKEYREJECTED, "EKEYREJECTED"),
    (libc::EOWNERDEAD, "EOWNERDEAD"),
    (libc::ENOTRECOVERABLE, "ENOTRECOVERABLE"),
    (libc::ERFKILL, "ERFKILL"),
    (libc::EHWPOISON, "EHWPOISON"),
];

/// The symbolic name of a Linux errno, `NONE` for zero, and `E<number>` for
/// a number Linux does not define. Receipts and probe evidence carry the
/// name, never a bare number, because a number in a report is not a fact
/// anyone can check; an undefined one keeps its number, so nothing is lost.
#[must_use]
pub fn errno_name(errno: i32) -> std::borrow::Cow<'static, str> {
    if errno == 0 {
        return "NONE".into();
    }
    ERRNOS
        .iter()
        .find(|(number, _)| *number == errno)
        .map_or_else(|| format!("E{errno}").into(), |(_, name)| (*name).into())
}

/// The errno a symbolic name stands for: the inverse of [`errno_name`]
/// over the names it gives.
#[cfg(test)]
#[must_use]
pub fn errno_from_name(name: &str) -> Option<i32> {
    if name == "NONE" {
        return Some(0);
    }
    ERRNOS
        .iter()
        .find(|(_, known)| *known == name)
        .map(|(number, _)| *number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interior_nul_is_refused_before_the_syscall() {
        let bad = OsStr::from_bytes(b"/tmp/a\0b");
        assert_eq!(
            cstring_from_os(bad),
            Err(PathError::InteriorNul { offset: 6 })
        );
    }

    #[test]
    fn empty_path_is_refused() {
        assert_eq!(cstring_from_path(Path::new("")), Err(PathError::Empty));
    }

    #[test]
    fn ordinary_path_converts() {
        let ok = cstring_from_path(Path::new("/tmp/x")).unwrap();
        assert_eq!(ok.as_bytes(), b"/tmp/x");
    }

    #[test]
    fn non_utf8_path_converts_losslessly() {
        let raw = OsStr::from_bytes(b"/tmp/\xff\xfe");
        let c = cstring_from_os(raw).unwrap();
        assert_eq!(c.as_bytes(), b"/tmp/\xff\xfe");
    }

    #[test]
    fn pipe_integers_are_little_endian_whatever_the_host() {
        assert_eq!(errno_bytes(libc::ENOENT), [2, 0, 0, 0]);
        assert_eq!(errno_from_bytes(errno_bytes(-7)), -7);
        assert_eq!(trace_data_bytes(0x1234), [0x34, 0x12]);
        assert_eq!(trace_data_from_bytes(trace_data_bytes(0xbeef)), 0xbeef);
    }

    #[test]
    fn errno_names_round_trip() {
        for (number, name) in ERRNOS {
            assert_eq!(errno_name(*number), *name);
            assert_eq!(errno_from_name(name), Some(*number), "{name}");
        }
        assert_eq!(errno_from_name(&errno_name(0)), Some(0));
        let mut numbers: Vec<i32> = ERRNOS.iter().map(|(number, _)| *number).collect();
        numbers.dedup();
        assert_eq!(
            numbers.len(),
            ERRNOS.len(),
            "the table is in number order, no alias"
        );
        assert!(numbers.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn an_errno_linux_does_not_define_keeps_its_number() {
        assert_eq!(errno_name(libc::EKEYREVOKED), "EKEYREVOKED");
        assert_eq!(errno_name(4242), "E4242");
        assert_eq!(errno_name(-3), "E-3");
        assert_eq!(errno_from_name("E4242"), None);
    }
}
