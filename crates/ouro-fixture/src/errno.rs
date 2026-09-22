//! Errno name/value table.
//!
//! The fixture reports `errno` by name so a test can write `--expect EACCES`
//! instead of a number that differs between platforms. Only names present on
//! both supported platforms live in the shared table; Linux-only names are
//! added behind a `cfg`. Where two names share a value (`EAGAIN` /
//! `EWOULDBLOCK` on both, `EOPNOTSUPP` / `ENOTSUP` on Linux) the first entry
//! wins the reverse lookup, so the reported name is stable.

use std::ffi::c_int;

macro_rules! table {
    ($($name:ident),* $(,)?) => {
        &[$((stringify!($name), libc::$name)),*]
    };
}

const SHARED: &[(&str, c_int)] = table![
    EPERM,
    ENOENT,
    ESRCH,
    EINTR,
    EIO,
    ENXIO,
    E2BIG,
    ENOEXEC,
    EBADF,
    ECHILD,
    EAGAIN,
    EWOULDBLOCK,
    ENOMEM,
    EACCES,
    EFAULT,
    ENOTBLK,
    EBUSY,
    EEXIST,
    EXDEV,
    ENODEV,
    ENOTDIR,
    EISDIR,
    EINVAL,
    ENFILE,
    EMFILE,
    ENOTTY,
    ETXTBSY,
    EFBIG,
    ENOSPC,
    ESPIPE,
    EROFS,
    EMLINK,
    EPIPE,
    EDOM,
    ERANGE,
    EDEADLK,
    ENAMETOOLONG,
    ENOLCK,
    ENOSYS,
    ENOTEMPTY,
    ELOOP,
    ENOMSG,
    EIDRM,
    EOVERFLOW,
    EILSEQ,
    ECANCELED,
    ESTALE,
    EDQUOT,
    ENOTSOCK,
    EDESTADDRREQ,
    EMSGSIZE,
    EPROTOTYPE,
    ENOPROTOOPT,
    EPROTONOSUPPORT,
    ESOCKTNOSUPPORT,
    EOPNOTSUPP,
    ENOTSUP,
    EPFNOSUPPORT,
    EAFNOSUPPORT,
    EADDRINUSE,
    EADDRNOTAVAIL,
    ENETDOWN,
    ENETUNREACH,
    ENETRESET,
    ECONNABORTED,
    ECONNRESET,
    ENOBUFS,
    EISCONN,
    ENOTCONN,
    ESHUTDOWN,
    ETOOMANYREFS,
    ETIMEDOUT,
    ECONNREFUSED,
    EHOSTDOWN,
    EHOSTUNREACH,
    EALREADY,
    EINPROGRESS,
    ENOTRECOVERABLE,
    EOWNERDEAD,
];

#[cfg(target_os = "linux")]
const EXTRA: &[(&str, c_int)] = table![
    ECHRNG,
    EBADE,
    ENOTUNIQ,
    EREMOTEIO,
    ENOMEDIUM,
    EMEDIUMTYPE,
    ENOKEY,
    EKEYEXPIRED,
    EKEYREVOKED,
    EKEYREJECTED,
    ERFKILL,
    EHWPOISON,
    ELIBBAD,
    ERESTART,
    EUCLEAN,
];

#[cfg(not(target_os = "linux"))]
const EXTRA: &[(&str, c_int)] = &[];

/// The name for a raw errno value, or `None` when this build has no name for it.
#[must_use]
pub fn name(value: c_int) -> Option<&'static str> {
    SHARED
        .iter()
        .chain(EXTRA.iter())
        .find(|(_, v)| *v == value)
        .map(|(n, _)| *n)
}

/// The raw value for an errno name, case-sensitive, or `None` when unknown here.
#[must_use]
pub fn value(name: &str) -> Option<c_int> {
    SHARED
        .iter()
        .chain(EXTRA.iter())
        .find(|(n, _)| *n == name)
        .map(|(_, v)| *v)
}

/// Every name this build knows, for a usage-error message.
#[must_use]
pub fn known_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = SHARED.iter().chain(EXTRA.iter()).map(|(n, _)| *n).collect();
    names.sort_unstable();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_common_errno() {
        assert_eq!(value("ENOENT"), Some(libc::ENOENT));
        assert_eq!(name(libc::ENOENT), Some("ENOENT"));
        assert_eq!(name(libc::EACCES), Some("EACCES"));
    }

    #[test]
    fn unknown_names_and_values_stay_unknown() {
        assert_eq!(value("ENOSUCHERRNO"), None);
        assert_eq!(value("enoent"), None, "lookup is case sensitive");
        assert_eq!(name(-1), None);
        assert_eq!(name(0), None, "0 is not an error");
    }

    #[test]
    fn aliases_resolve_to_the_first_listed_name() {
        // Both names must still resolve to the value; only the reverse lookup
        // is forced to one stable answer.
        assert_eq!(value("EAGAIN"), value("EWOULDBLOCK"));
        assert_eq!(name(libc::EAGAIN), Some("EAGAIN"));
        #[cfg(target_os = "linux")]
        assert_eq!(name(libc::EOPNOTSUPP), Some("EOPNOTSUPP"));
    }

    #[test]
    fn the_table_is_not_empty_and_is_sorted_for_messages() {
        let names = known_names();
        assert!(
            names.len() > 50,
            "table unexpectedly small: {}",
            names.len()
        );
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }
}
