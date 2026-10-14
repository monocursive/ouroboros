//! The user and group databases, as far as this tool asks them.
//!
//! `getpwuid_r` and `getgrgid_r` write the entry's strings into a buffer the
//! caller supplies and answer `ERANGE` when it is too small, which a group
//! with many members (`docker`, `sudo` on a shared host) easily makes it. A
//! lookup here retries with a buffer twice the size, up to
//! [`BUFFER_MAX`], so an entry is either read whole or the lookup fails: it
//! is never mistaken for an absent one.

use std::ffi::CStr;
use std::io;
use std::sync::Mutex;

/// The first buffer a lookup tries.
const BUFFER_START: usize = 16 * 1024;
/// The largest buffer a lookup grows to before it fails with `ERANGE`. A
/// directory group with thousands of members (an LDAP or AD `docker` or
/// `sudo`) needs far more than [`BUFFER_START`]; no real entry needs this
/// much.
pub const BUFFER_MAX: usize = 16 * 1024 * 1024;

/// An account of the user database.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct User {
    /// Its name.
    pub name: Vec<u8>,
    /// Its primary group.
    pub primary_gid: u32,
}

/// A group of the group database.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Group {
    /// Its name.
    pub name: Vec<u8>,
    /// The members it lists (not the accounts whose primary group it is).
    pub members: Vec<Vec<u8>>,
}

/// Runs `call` with a buffer that grows while it answers `ERANGE`.
///
/// `call` returns the lookup's own result: `Ok(None)` for no such entry,
/// `Err(errno)` for a failed lookup.
fn with_growing_buffer<T>(
    max: usize,
    mut call: impl FnMut(&mut [u8]) -> Result<Option<T>, libc::c_int>,
) -> io::Result<Option<T>> {
    let mut size = BUFFER_START.min(max);
    loop {
        let mut buffer = vec![0_u8; size];
        match call(&mut buffer) {
            Ok(found) => return Ok(found),
            Err(libc::ERANGE) if size < max => size = size.saturating_mul(2).min(max),
            Err(errno) => return Err(io::Error::from_raw_os_error(errno)),
        }
    }
}

/// The account `uid`, or `None` when the database has none.
///
/// # Errors
/// The lookup failed: an error of the database, or an entry larger than
/// [`BUFFER_MAX`].
pub fn user(uid: u32) -> io::Result<Option<User>> {
    with_growing_buffer(BUFFER_MAX, |buffer| {
        // SAFETY: `passwd` is a plain C struct; all-zero is a valid value
        // that getpwuid_r overwrites before it is read.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is to a live local, the length is the
        // buffer's own, and getpwuid_r writes only within them.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &raw mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut result,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        if result.is_null() || entry.pw_name.is_null() {
            return Ok(None);
        }
        // SAFETY: getpwuid_r succeeded, so pw_name points at a
        // NUL-terminated string inside `buffer`, which is still alive.
        let name = unsafe { CStr::from_ptr(entry.pw_name) }.to_bytes().to_vec();
        Ok(Some(User {
            name,
            primary_gid: entry.pw_gid,
        }))
    })
}

/// The group `gid`, or `None` when the database has none.
///
/// # Errors
/// The lookup failed: an error of the database, or an entry larger than
/// [`BUFFER_MAX`].
pub fn group(gid: u32) -> io::Result<Option<Group>> {
    with_growing_buffer(BUFFER_MAX, |buffer| {
        // SAFETY: `group` is a plain C struct; all-zero is a valid value
        // that getgrgid_r overwrites before it is read.
        let mut entry: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        // SAFETY: every pointer is to a live local, the length is the
        // buffer's own, and getgrgid_r writes only within them.
        let rc = unsafe {
            libc::getgrgid_r(
                gid,
                &raw mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut result,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        if result.is_null() || entry.gr_name.is_null() {
            return Ok(None);
        }
        // SAFETY: getgrgid_r succeeded, so gr_name points at a
        // NUL-terminated string inside `buffer`, which is still alive.
        let name = unsafe { CStr::from_ptr(entry.gr_name) }.to_bytes().to_vec();
        let mut members = Vec::new();
        let mut slot = entry.gr_mem;
        while !slot.is_null() {
            // SAFETY: gr_mem is a NULL-terminated array of pointers into
            // `buffer`; `slot` has not passed its terminator.
            let member = unsafe { *slot };
            if member.is_null() {
                break;
            }
            // SAFETY: each member points at a NUL-terminated string inside
            // `buffer`.
            members.push(unsafe { CStr::from_ptr(member) }.to_bytes().to_vec());
            // SAFETY: the array continues until its NULL terminator, which
            // has not been reached.
            slot = unsafe { slot.add(1) };
        }
        Ok(Some(Group { name, members }))
    })
}

/// The facts the private-group rule needs, separated from the lookups so the
/// rule can be tested without depending on the host's accounts.
pub(crate) struct Facts<'a> {
    /// The owner's name and primary group, if the owner is known.
    pub owner: Option<(&'a [u8], u32)>,
    /// The group's listed members, if the group is known.
    pub members: Option<Vec<Vec<u8>>>,
    /// Whether another account has this group as its primary group.
    pub another_primary: bool,
}

/// The rule of `state::writable_by_others` for a group-writable object:
/// the group is the owner's primary group, lists no member but the owner,
/// and is no other account's primary group.
pub(crate) fn private(gid: u32, facts: &Facts<'_>) -> bool {
    let Some((name, primary)) = facts.owner else {
        return false;
    };
    let Some(members) = &facts.members else {
        return false;
    };
    primary == gid
        && members.iter().all(|member| member.as_slice() == name)
        && !facts.another_primary
}

/// `getpwent` walks one process-wide position.
static PASSWD_WALK: Mutex<()> = Mutex::new(());

/// Whether `gid` is private to `uid` ([`private`]); an account or group the
/// database cannot read is not.
pub(crate) fn group_is_private_to(uid: u32, gid: u32) -> bool {
    let Ok(Some(owner)) = user(uid) else {
        return false;
    };
    let facts = Facts {
        owner: Some((&owner.name, owner.primary_gid)),
        members: group(gid).ok().flatten().map(|group| group.members),
        another_primary: another_primary(uid, gid),
    };
    private(gid, &facts)
}

fn another_primary(uid: u32, gid: u32) -> bool {
    let _guard = crate::sync::lock(&PASSWD_WALK);
    let mut found = false;
    // SAFETY: setpwent/getpwent/endpwent share one process-wide position,
    // which the mutex serializes within this process; each entry is read
    // before the next call.
    unsafe {
        libc::setpwent();
        loop {
            let entry = libc::getpwent();
            if entry.is_null() {
                break;
            }
            if (*entry).pw_gid == gid && (*entry).pw_uid != uid {
                found = true;
                break;
            }
        }
        libc::endpwent();
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry too large for the first buffer is read whole from a larger
    /// one; one too large for every buffer fails, and is never absent.
    #[test]
    fn a_lookup_grows_its_buffer_on_erange_up_to_its_bound() {
        let mut sizes = Vec::new();
        let found = with_growing_buffer(BUFFER_MAX, |buffer| {
            sizes.push(buffer.len());
            if buffer.len() < 100_000 {
                Err(libc::ERANGE)
            } else {
                Ok(Some(buffer.len()))
            }
        })
        .unwrap();
        assert_eq!(found, Some(131_072));
        assert_eq!(sizes, [16_384, 32_768, 65_536, 131_072]);

        let error = with_growing_buffer(65_536, |_| Err::<Option<()>, _>(libc::ERANGE))
            .expect_err("never large enough");
        assert_eq!(error.raw_os_error(), Some(libc::ERANGE));
        let error = with_growing_buffer(BUFFER_MAX, |_| Err::<Option<()>, _>(libc::EIO))
            .expect_err("another error is not retried");
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(
            with_growing_buffer(BUFFER_MAX, |_| Ok::<Option<()>, _>(None)).unwrap(),
            None
        );
    }

    /// This process's own account and its primary group are found.
    #[test]
    fn this_processs_account_and_group_are_found() {
        // SAFETY: getuid and getgid take no arguments and cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let user = user(uid).unwrap().expect("this account");
        assert!(!user.name.is_empty());
        assert!(group(gid).unwrap().is_some());
    }
}
