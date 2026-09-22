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

/// The symbolic name of a Linux errno, or `E<number>` when it is not one this
/// project names. Receipts and probe evidence carry the name, never a bare
/// number, because a number in a report is not a fact anyone can check.
#[must_use]
pub fn errno_name(errno: i32) -> &'static str {
    match errno {
        0 => "NONE",
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EINTR => "EINTR",
        libc::EIO => "EIO",
        libc::ENXIO => "ENXIO",
        libc::E2BIG => "E2BIG",
        libc::ENOEXEC => "ENOEXEC",
        libc::EBADF => "EBADF",
        libc::ECHILD => "ECHILD",
        libc::EAGAIN => "EAGAIN",
        libc::ENOMEM => "ENOMEM",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::EBUSY => "EBUSY",
        libc::EEXIST => "EEXIST",
        libc::EXDEV => "EXDEV",
        libc::ENODEV => "ENODEV",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::EINVAL => "EINVAL",
        libc::ENFILE => "ENFILE",
        libc::EMFILE => "EMFILE",
        libc::ENOTTY => "ENOTTY",
        libc::EFBIG => "EFBIG",
        libc::ENOSPC => "ENOSPC",
        libc::ESPIPE => "ESPIPE",
        libc::EROFS => "EROFS",
        libc::EMLINK => "EMLINK",
        libc::EPIPE => "EPIPE",
        libc::ERANGE => "ERANGE",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ENOSYS => "ENOSYS",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::ELOOP => "ELOOP",
        libc::ENODATA => "ENODATA",
        libc::EPROTO => "EPROTO",
        libc::EOVERFLOW => "EOVERFLOW",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::ENETUNREACH => "ENETUNREACH",
        libc::ENETDOWN => "ENETDOWN",
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::ETIMEDOUT => "ETIMEDOUT",
        libc::EHOSTUNREACH => "EHOSTUNREACH",
        libc::EADDRNOTAVAIL => "EADDRNOTAVAIL",
        libc::EPROTONOSUPPORT => "EPROTONOSUPPORT",
        // §11.2 names it for net.connect: the canonical non-blocking
        // in-progress return, not an anonymous number.
        libc::EINPROGRESS => "EINPROGRESS",
        libc::ESTALE => "ESTALE",
        libc::EDQUOT => "EDQUOT",
        _ => "E?",
    }
}

/// Parse a symbolic errno name back to its number. Used by tests and by the
/// probe helper that reports results across a pipe.
#[must_use]
pub fn errno_from_name(name: &str) -> Option<i32> {
    const KNOWN: &[i32] = &[
        libc::EPERM,
        libc::ENOENT,
        libc::ESRCH,
        libc::EINTR,
        libc::EIO,
        libc::EBADF,
        libc::EAGAIN,
        libc::ENOMEM,
        libc::EACCES,
        libc::EFAULT,
        libc::EBUSY,
        libc::EEXIST,
        libc::ENODEV,
        libc::ENOTDIR,
        libc::EISDIR,
        libc::EINVAL,
        libc::EROFS,
        libc::ENOSYS,
        libc::ENOTEMPTY,
        libc::ELOOP,
        libc::EAFNOSUPPORT,
        libc::ENETUNREACH,
        libc::ECONNREFUSED,
        libc::EPROTONOSUPPORT,
    ];
    if name == "NONE" {
        return Some(0);
    }
    KNOWN.iter().copied().find(|e| errno_name(*e) == name)
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
    fn errno_names_round_trip() {
        for e in [libc::EPERM, libc::EROFS, libc::ENOSYS, libc::ENETUNREACH] {
            assert_eq!(errno_from_name(errno_name(e)), Some(e));
        }
    }
}
