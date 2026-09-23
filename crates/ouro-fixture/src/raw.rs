//! The raw syscall layer.
//!
//! The fixture exists so a tracer sees *exactly* the syscall the test named.
//! On Linux every variant therefore goes through `libc::syscall(SYS_x, ...)`:
//! the glibc wrapper `open()` issues `openat`, `mkdir()` may issue `mkdirat`,
//! and so on, so calling the wrappers would silently rename the operation in
//! the trace. On macOS there is no supported raw syscall interface, so the
//! same-named libc wrapper is used and this is stated in the report.
//!
//! Syscalls that the architecture does not have (`open`, `mkdir`, `rename`,
//! `unlink`, `rmdir`, `link`, `symlink`, `creat`, `mknod` do not exist on Linux
//! `aarch64`) and syscalls that the platform does not have (`openat2`,
//! `renameat2`, `execveat`, `mknodat` outside Linux) return [`Attempt::Absent`], which is
//! jail-v1 §11.2's "calls absent on an architecture are identified as absent".
//! An absent call is never a satisfied expectation.
//!
//! Every `unsafe` block here is a syscall whose preconditions are: the path
//! pointers come from live `CString`s owned by the caller for the whole call
//! (no interior NUL can reach here, [`cpath`] refuses first), the argv/envp
//! arrays are NULL-terminated arrays of live pointers, and the `open_how`
//! pointer is a live, correctly sized `#[repr(C)]` value.
//!
//! The socket calls (`socket`, `socketpair`, `bind`, `listen`, `accept4`,
//! `sendto`, `sendmsg`, `recvmsg`) and the inner-sandbox calls (`prctl`,
//! `landlock_*`, `seccomp`) follow the same rule. Addresses arrive as
//! [`crate::sockaddr::SockAddr`], whose length never exceeds its storage;
//! the calls that take a structure with embedded pointers (`sendmsg`,
//! `recvmsg`, `landlock_*`, `seccomp`) are `unsafe fn`s whose contract the
//! caller states at the call site. Darwin has no `accept4`, so `accept` is
//! used there and `ACCEPT_OP` names the call the line reports.

use std::ffi::{CString, OsStr, c_int, c_long};
use std::os::unix::ffi::OsStrExt;

/// What a raw call did.
pub enum Attempt {
    /// The syscall ran; `ret` is its signed return, `errno` its raw errno when
    /// `ret` is negative.
    Performed { ret: i64, errno: Option<c_int> },
    /// The syscall does not exist in this build. Carries the reason for the
    /// report line.
    Absent(String),
}

impl Attempt {
    fn finish(ret: c_long) -> Attempt {
        let errno = if ret < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        // `c_long` is 32 bits on 32-bit targets, so this widening is not
        // always the no-op it is on the platforms this project builds for.
        #[allow(clippy::unnecessary_cast)]
        let ret = ret as i64;
        Attempt::Performed { ret, errno }
    }
}

/// A path that could not be handed to a syscall at all.
#[derive(Debug, PartialEq, Eq)]
pub struct PathRefused {
    pub reason: &'static str,
}

/// Convert an OS path to a NUL-terminated C string.
///
/// A path containing an interior NUL is refused *before* any syscall runs: the
/// kernel would otherwise silently see a truncated path and operate on a
/// different file than the test named. This is the unsafe boundary the fixture
/// must not cross, and `tests/fixture_modes.rs` tries to violate it.
pub fn cpath(p: &OsStr) -> Result<CString, PathRefused> {
    CString::new(p.as_bytes()).map_err(|_| PathRefused {
        reason: "interior_nul",
    })
}

/// Whether the non-`at` syscalls (`open`, `creat`, `mkdir`, `rename`,
/// `unlink`, `rmdir`, `link`, `symlink`, `mknod`) have syscall numbers here.
/// Linux `aarch64` and other newer ports dropped them; macOS keeps all of them.
#[must_use]
pub const fn has_legacy_syscalls() -> bool {
    !cfg!(target_os = "linux") || cfg!(any(target_arch = "x86_64", target_arch = "x86"))
}

/// How a given operation reached the kernel, for the report line.
#[must_use]
pub const fn mechanism() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux_raw_syscall"
    }
    #[cfg(not(target_os = "linux"))]
    {
        "libc_wrapper"
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Attempt, c_int, c_long};
    use std::ffi::c_char;

    // Syscall numbers from 424 upwards are architecture independent, so
    // `openat2` (437) is safe to name directly; the older ones differ per
    // architecture and come from `libc`.
    const SYS_OPENAT2: c_long = 437;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    /// Legacy non-`at` syscalls exist only where the architecture kept them.
    /// Unused on x86 and x86_64, which kept every one of them.
    #[allow(dead_code)]
    fn legacy_absent(name: &str) -> Attempt {
        Attempt::Absent(format!(
            "{name} has no syscall number on linux/{}; use the *at variant",
            std::env::consts::ARCH
        ))
    }

    pub(crate) fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: u32) -> Attempt {
        // SAFETY: `path` is a live NUL-terminated string owned by the caller
        // for the duration of the call; the remaining arguments are plain
        // integers widened to the register width the syscall ABI reads.
        let r = unsafe {
            libc::syscall(
                libc::SYS_openat,
                dirfd as c_long,
                path,
                flags as c_long,
                mode as c_long,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn open(path: *const c_char, flags: c_int, mode: u32) -> Attempt {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // SAFETY: as `openat`; `path` outlives the call.
            let r = unsafe { libc::syscall(libc::SYS_open, path, flags as c_long, mode as c_long) };
            Attempt::finish(r)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            let _ = (path, flags, mode);
            legacy_absent("open")
        }
    }

    pub(crate) fn creat(path: *const c_char, mode: u32) -> Attempt {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // SAFETY: as `openat`; `path` outlives the call.
            let r = unsafe { libc::syscall(libc::SYS_creat, path, mode as c_long) };
            Attempt::finish(r)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            let _ = (path, mode);
            legacy_absent("creat")
        }
    }

    pub(crate) fn openat2(dirfd: c_int, path: *const c_char, flags: c_int, mode: u32) -> Attempt {
        let how = OpenHow {
            flags: flags as u32 as u64,
            mode: u64::from(mode),
            resolve: 0,
        };
        // SAFETY: `path` outlives the call; `&how` is a live, correctly sized
        // `open_how` and the size argument matches `size_of::<OpenHow>()`.
        let r = unsafe {
            libc::syscall(
                SYS_OPENAT2,
                dirfd as c_long,
                path,
                std::ptr::addr_of!(how),
                size_of::<OpenHow>() as c_long,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn mkdir(path: *const c_char, mode: u32) -> Attempt {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // SAFETY: `path` outlives the call.
            let r = unsafe { libc::syscall(libc::SYS_mkdir, path, mode as c_long) };
            Attempt::finish(r)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            let _ = (path, mode);
            legacy_absent("mkdir")
        }
    }

    pub(crate) fn mkdirat(dirfd: c_int, path: *const c_char, mode: u32) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r = unsafe { libc::syscall(libc::SYS_mkdirat, dirfd as c_long, path, mode as c_long) };
        Attempt::finish(r)
    }

    pub(crate) fn rename(from: *const c_char, to: *const c_char) -> Attempt {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // SAFETY: both paths outlive the call.
            let r = unsafe { libc::syscall(libc::SYS_rename, from, to) };
            Attempt::finish(r)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            let _ = (from, to);
            legacy_absent("rename")
        }
    }

    pub(crate) fn renameat(
        olddirfd: c_int,
        from: *const c_char,
        newdirfd: c_int,
        to: *const c_char,
    ) -> Attempt {
        // SAFETY: both paths outlive the call.
        let r = unsafe {
            libc::syscall(
                libc::SYS_renameat,
                olddirfd as c_long,
                from,
                newdirfd as c_long,
                to,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn renameat2(
        olddirfd: c_int,
        from: *const c_char,
        newdirfd: c_int,
        to: *const c_char,
        flags: u32,
    ) -> Attempt {
        // SAFETY: both paths outlive the call.
        let r = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                olddirfd as c_long,
                from,
                newdirfd as c_long,
                to,
                flags as c_long,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn unlink(path: *const c_char) -> Attempt {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // SAFETY: `path` outlives the call.
            let r = unsafe { libc::syscall(libc::SYS_unlink, path) };
            Attempt::finish(r)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            let _ = path;
            legacy_absent("unlink")
        }
    }

    pub(crate) fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r =
            unsafe { libc::syscall(libc::SYS_unlinkat, dirfd as c_long, path, flags as c_long) };
        Attempt::finish(r)
    }

    pub(crate) fn rmdir(path: *const c_char) -> Attempt {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // SAFETY: `path` outlives the call.
            let r = unsafe { libc::syscall(libc::SYS_rmdir, path) };
            Attempt::finish(r)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            let _ = path;
            legacy_absent("rmdir")
        }
    }

    pub(crate) fn link(from: *const c_char, to: *const c_char) -> Attempt {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // SAFETY: both paths outlive the call.
            let r = unsafe { libc::syscall(libc::SYS_link, from, to) };
            Attempt::finish(r)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            let _ = (from, to);
            legacy_absent("link")
        }
    }

    pub(crate) fn linkat(
        olddirfd: c_int,
        from: *const c_char,
        newdirfd: c_int,
        to: *const c_char,
        flags: c_int,
    ) -> Attempt {
        // SAFETY: both paths outlive the call.
        let r = unsafe {
            libc::syscall(
                libc::SYS_linkat,
                olddirfd as c_long,
                from,
                newdirfd as c_long,
                to,
                flags as c_long,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn symlink(target: *const c_char, linkpath: *const c_char) -> Attempt {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // SAFETY: both paths outlive the call.
            let r = unsafe { libc::syscall(libc::SYS_symlink, target, linkpath) };
            Attempt::finish(r)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            let _ = (target, linkpath);
            legacy_absent("symlink")
        }
    }

    pub(crate) fn symlinkat(
        target: *const c_char,
        newdirfd: c_int,
        linkpath: *const c_char,
    ) -> Attempt {
        // SAFETY: both paths outlive the call.
        let r = unsafe { libc::syscall(libc::SYS_symlinkat, target, newdirfd as c_long, linkpath) };
        Attempt::finish(r)
    }

    pub(crate) fn execve(
        path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> Attempt {
        // SAFETY: `path` outlives the call; `argv` and `envp` are
        // NULL-terminated arrays of live NUL-terminated strings.
        let r = unsafe { libc::syscall(libc::SYS_execve, path, argv, envp) };
        Attempt::finish(r)
    }

    pub(crate) fn execveat(
        dirfd: c_int,
        path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
        flags: c_int,
    ) -> Attempt {
        // SAFETY: as `execve`; `dirfd` and `flags` are plain integers.
        let r = unsafe {
            libc::syscall(
                libc::SYS_execveat,
                dirfd as c_long,
                path,
                argv,
                envp,
                flags as c_long,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn connect(fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> Attempt {
        // SAFETY: `addr` points to a live sockaddr of at least `len` bytes,
        // owned by the caller for the duration of the call.
        let r = unsafe { libc::syscall(libc::SYS_connect, fd as c_long, addr, len as c_long) };
        Attempt::finish(r)
    }

    /// The syscall `accept` below issues, for the report line.
    pub(crate) const ACCEPT_OP: &str = "accept4";

    pub(crate) fn socket(domain: c_int, ty: c_int, protocol: c_int) -> Attempt {
        // SAFETY: plain integers; the kernel allocates a descriptor or fails.
        let r = unsafe {
            libc::syscall(
                libc::SYS_socket,
                domain as c_long,
                ty as c_long,
                protocol as c_long,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn socketpair(
        domain: c_int,
        ty: c_int,
        protocol: c_int,
        sv: &mut [c_int; 2],
    ) -> Attempt {
        // SAFETY: `sv` is a live, exclusively borrowed array of two ints,
        // which is exactly what `socketpair` writes.
        let r = unsafe {
            libc::syscall(
                libc::SYS_socketpair,
                domain as c_long,
                ty as c_long,
                protocol as c_long,
                sv.as_mut_ptr(),
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn bind(fd: c_int, addr: &crate::sockaddr::SockAddr) -> Attempt {
        // SAFETY: `SockAddr` guarantees its length never exceeds its live
        // storage, which is borrowed for the whole call.
        let r = unsafe {
            libc::syscall(
                libc::SYS_bind,
                fd as c_long,
                addr.as_ptr(),
                addr.len() as c_long,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn listen(fd: c_int, backlog: c_int) -> Attempt {
        // SAFETY: plain integers.
        let r = unsafe { libc::syscall(libc::SYS_listen, fd as c_long, backlog as c_long) };
        Attempt::finish(r)
    }

    /// `accept4(fd, NULL, NULL, SOCK_CLOEXEC)`: the peer address is not asked
    /// for, so no buffer crosses the boundary.
    pub(crate) fn accept(fd: c_int) -> Attempt {
        // SAFETY: both address arguments are NULL, which the kernel accepts
        // as "do not report the peer"; the rest are plain integers.
        let r = unsafe {
            libc::syscall(
                libc::SYS_accept4,
                fd as c_long,
                std::ptr::null_mut::<libc::sockaddr>(),
                std::ptr::null_mut::<libc::socklen_t>(),
                libc::SOCK_CLOEXEC as c_long,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn sendto(
        fd: c_int,
        buf: &[u8],
        flags: c_int,
        addr: &crate::sockaddr::SockAddr,
    ) -> Attempt {
        // SAFETY: `buf` is a live slice read for exactly its length; `addr`
        // is a live `SockAddr` whose length never exceeds its storage.
        let r = unsafe {
            libc::syscall(
                libc::SYS_sendto,
                fd as c_long,
                buf.as_ptr(),
                buf.len() as c_long,
                flags as c_long,
                addr.as_ptr(),
                addr.len() as c_long,
            )
        };
        Attempt::finish(r)
    }

    /// # Safety
    ///
    /// Every pointer inside `msg` (name, iovecs, control buffer) must point to
    /// live memory of at least the length recorded beside it.
    pub(crate) unsafe fn sendmsg(fd: c_int, msg: *const libc::msghdr, flags: c_int) -> Attempt {
        // SAFETY: the caller upholds this function's contract.
        let r = unsafe { libc::syscall(libc::SYS_sendmsg, fd as c_long, msg, flags as c_long) };
        Attempt::finish(r)
    }

    /// # Safety
    ///
    /// Every pointer inside `msg` must point to live, writable memory of at
    /// least the length recorded beside it.
    pub(crate) unsafe fn recvmsg(fd: c_int, msg: *mut libc::msghdr, flags: c_int) -> Attempt {
        // SAFETY: the caller upholds this function's contract.
        let r = unsafe { libc::syscall(libc::SYS_recvmsg, fd as c_long, msg, flags as c_long) };
        Attempt::finish(r)
    }

    pub(crate) fn prctl(option: c_int, arg2: u64) -> Attempt {
        // SAFETY: `PR_SET_NO_NEW_PRIVS`-style options take integers only; the
        // unused arguments are zero as the kernel requires.
        let r = unsafe {
            libc::syscall(
                libc::SYS_prctl,
                option as c_long,
                arg2 as c_long,
                0 as c_long,
                0 as c_long,
                0 as c_long,
            )
        };
        Attempt::finish(r)
    }

    /// # Safety
    ///
    /// `attr` is NULL with `size` 0, or points to `size` live bytes laid out
    /// as `struct landlock_ruleset_attr` (or a prefix of it).
    pub(crate) unsafe fn landlock_create_ruleset(
        attr: *const libc::c_void,
        size: usize,
        flags: u32,
    ) -> Attempt {
        // SAFETY: the caller upholds this function's contract.
        let r = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                attr,
                size as c_long,
                flags as c_long,
            )
        };
        Attempt::finish(r)
    }

    /// # Safety
    ///
    /// `attr` points to a live attribute of the layout `rule_type` names.
    pub(crate) unsafe fn landlock_add_rule(
        ruleset_fd: c_int,
        rule_type: c_int,
        attr: *const libc::c_void,
        flags: u32,
    ) -> Attempt {
        // SAFETY: the caller upholds this function's contract.
        let r = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset_fd as c_long,
                rule_type as c_long,
                attr,
                flags as c_long,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn landlock_restrict_self(ruleset_fd: c_int, flags: u32) -> Attempt {
        // SAFETY: plain integers.
        let r = unsafe {
            libc::syscall(
                libc::SYS_landlock_restrict_self,
                ruleset_fd as c_long,
                flags as c_long,
            )
        };
        Attempt::finish(r)
    }

    /// # Safety
    ///
    /// `prog` points to a live `sock_fprog` whose `filter` points to `len`
    /// live instructions.
    pub(crate) unsafe fn seccomp_set_mode_filter(
        prog: *const libc::sock_fprog,
        flags: u32,
    ) -> Attempt {
        // SAFETY: the caller upholds this function's contract.
        let r = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER as c_long,
                flags as c_long,
                prog,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn mknod(path: *const c_char, mode: u32, dev: u64) -> Attempt {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            // SAFETY: `path` outlives the call; `mode` and `dev` are plain
            // integers widened to the register width the ABI reads.
            let r = unsafe { libc::syscall(libc::SYS_mknod, path, mode as c_long, dev as c_long) };
            Attempt::finish(r)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            let _ = (path, mode, dev);
            legacy_absent("mknod")
        }
    }

    pub(crate) fn mknodat(dirfd: c_int, path: *const c_char, mode: u32, dev: u64) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r = unsafe {
            libc::syscall(
                libc::SYS_mknodat,
                dirfd as c_long,
                path,
                mode as c_long,
                dev as c_long,
            )
        };
        Attempt::finish(r)
    }

    pub(crate) fn truncate(path: *const c_char, length: i64) -> Attempt {
        // SAFETY: `path` outlives the call; `length` is a plain integer.
        let r = unsafe { libc::syscall(libc::SYS_truncate, path, length as c_long) };
        Attempt::finish(r)
    }

    pub(crate) fn ftruncate(fd: c_int, length: i64) -> Attempt {
        // SAFETY: `fd` is a descriptor the caller owns; `length` is a plain
        // integer. Nothing is dereferenced.
        let r = unsafe { libc::syscall(libc::SYS_ftruncate, fd as c_long, length as c_long) };
        Attempt::finish(r)
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{Attempt, c_int, c_long};
    use std::ffi::c_char;

    macro_rules! linux_only {
        ($name:literal) => {
            Attempt::Absent(format!(
                "{} is a Linux syscall; this build targets {}",
                $name,
                std::env::consts::OS
            ))
        };
    }

    pub(crate) fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: u32) -> Attempt {
        // SAFETY: `path` is a live NUL-terminated string owned by the caller.
        let r = unsafe { libc::openat(dirfd, path, flags, mode) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn open(path: *const c_char, flags: c_int, mode: u32) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r = unsafe { libc::open(path, flags, mode) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn creat(path: *const c_char, mode: u32) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r = unsafe { libc::creat(path, mode as libc::mode_t) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn openat2(
        _dirfd: c_int,
        _path: *const c_char,
        _flags: c_int,
        _mode: u32,
    ) -> Attempt {
        linux_only!("openat2")
    }

    pub(crate) fn mkdir(path: *const c_char, mode: u32) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r = unsafe { libc::mkdir(path, mode as libc::mode_t) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn mkdirat(dirfd: c_int, path: *const c_char, mode: u32) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r = unsafe { libc::mkdirat(dirfd, path, mode as libc::mode_t) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn rename(from: *const c_char, to: *const c_char) -> Attempt {
        // SAFETY: both paths outlive the call.
        let r = unsafe { libc::rename(from, to) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn renameat(
        olddirfd: c_int,
        from: *const c_char,
        newdirfd: c_int,
        to: *const c_char,
    ) -> Attempt {
        // SAFETY: both paths outlive the call.
        let r = unsafe { libc::renameat(olddirfd, from, newdirfd, to) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn renameat2(
        _olddirfd: c_int,
        _from: *const c_char,
        _newdirfd: c_int,
        _to: *const c_char,
        _flags: u32,
    ) -> Attempt {
        linux_only!("renameat2")
    }

    pub(crate) fn unlink(path: *const c_char) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r = unsafe { libc::unlink(path) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r = unsafe { libc::unlinkat(dirfd, path, flags) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn rmdir(path: *const c_char) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r = unsafe { libc::rmdir(path) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn link(from: *const c_char, to: *const c_char) -> Attempt {
        // SAFETY: both paths outlive the call.
        let r = unsafe { libc::link(from, to) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn linkat(
        olddirfd: c_int,
        from: *const c_char,
        newdirfd: c_int,
        to: *const c_char,
        flags: c_int,
    ) -> Attempt {
        // SAFETY: both paths outlive the call.
        let r = unsafe { libc::linkat(olddirfd, from, newdirfd, to, flags) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn symlink(target: *const c_char, linkpath: *const c_char) -> Attempt {
        // SAFETY: both paths outlive the call.
        let r = unsafe { libc::symlink(target, linkpath) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn symlinkat(
        target: *const c_char,
        newdirfd: c_int,
        linkpath: *const c_char,
    ) -> Attempt {
        // SAFETY: both paths outlive the call.
        let r = unsafe { libc::symlinkat(target, newdirfd, linkpath) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn execve(
        path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> Attempt {
        // SAFETY: `path` outlives the call; `argv`/`envp` are NULL-terminated
        // arrays of live NUL-terminated strings.
        let r = unsafe { libc::execve(path, argv, envp) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn execveat(
        _dirfd: c_int,
        _path: *const c_char,
        _argv: *const *const c_char,
        _envp: *const *const c_char,
        _flags: c_int,
    ) -> Attempt {
        linux_only!("execveat")
    }

    pub(crate) fn connect(fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> Attempt {
        // SAFETY: `addr` points to a live sockaddr of at least `len` bytes.
        let r = unsafe { libc::connect(fd, addr, len) };
        Attempt::finish(c_long::from(r))
    }

    /// Darwin has no `accept4`; `accept` is the call, and close-on-exec is set
    /// by the caller afterwards.
    pub(crate) const ACCEPT_OP: &str = "accept";

    pub(crate) fn socket(domain: c_int, ty: c_int, protocol: c_int) -> Attempt {
        // SAFETY: plain integers.
        let r = unsafe { libc::socket(domain, ty, protocol) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn socketpair(
        domain: c_int,
        ty: c_int,
        protocol: c_int,
        sv: &mut [c_int; 2],
    ) -> Attempt {
        // SAFETY: `sv` is a live, exclusively borrowed array of two ints.
        let r = unsafe { libc::socketpair(domain, ty, protocol, sv.as_mut_ptr()) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn bind(fd: c_int, addr: &crate::sockaddr::SockAddr) -> Attempt {
        // SAFETY: `SockAddr` guarantees its length never exceeds its storage.
        let r = unsafe { libc::bind(fd, addr.as_ptr(), addr.len()) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn listen(fd: c_int, backlog: c_int) -> Attempt {
        // SAFETY: plain integers.
        let r = unsafe { libc::listen(fd, backlog) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn accept(fd: c_int) -> Attempt {
        // SAFETY: both address arguments are NULL: the peer is not reported.
        let r = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn sendto(
        fd: c_int,
        buf: &[u8],
        flags: c_int,
        addr: &crate::sockaddr::SockAddr,
    ) -> Attempt {
        // SAFETY: `buf` is read for exactly its length; `addr` never claims
        // more than its storage.
        let r = unsafe {
            libc::sendto(
                fd,
                buf.as_ptr().cast::<libc::c_void>(),
                buf.len(),
                flags,
                addr.as_ptr(),
                addr.len(),
            )
        };
        #[allow(clippy::unnecessary_cast)]
        Attempt::finish(r as c_long)
    }

    /// # Safety
    ///
    /// Every pointer inside `msg` must point to live memory of at least the
    /// length recorded beside it.
    pub(crate) unsafe fn sendmsg(fd: c_int, msg: *const libc::msghdr, flags: c_int) -> Attempt {
        // SAFETY: the caller upholds this function's contract.
        let r = unsafe { libc::sendmsg(fd, msg, flags) };
        #[allow(clippy::unnecessary_cast)]
        Attempt::finish(r as c_long)
    }

    /// # Safety
    ///
    /// Every pointer inside `msg` must point to live, writable memory of at
    /// least the length recorded beside it.
    pub(crate) unsafe fn recvmsg(fd: c_int, msg: *mut libc::msghdr, flags: c_int) -> Attempt {
        // SAFETY: the caller upholds this function's contract.
        let r = unsafe { libc::recvmsg(fd, msg, flags) };
        #[allow(clippy::unnecessary_cast)]
        Attempt::finish(r as c_long)
    }

    pub(crate) fn mknod(path: *const c_char, mode: u32, dev: u64) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r = unsafe { libc::mknod(path, mode as libc::mode_t, dev as libc::dev_t) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn mknodat(_dirfd: c_int, _path: *const c_char, _mode: u32, _dev: u64) -> Attempt {
        // Darwin has no `mknodat`; `mkfifoat` is not the same syscall and
        // would be a different operation in a trace.
        linux_only!("mknodat")
    }

    pub(crate) fn truncate(path: *const c_char, length: i64) -> Attempt {
        // SAFETY: `path` outlives the call.
        let r = unsafe { libc::truncate(path, length as libc::off_t) };
        Attempt::finish(c_long::from(r))
    }

    pub(crate) fn ftruncate(fd: c_int, length: i64) -> Attempt {
        // SAFETY: `fd` is a descriptor the caller owns; nothing is dereferenced.
        let r = unsafe { libc::ftruncate(fd, length as libc::off_t) };
        Attempt::finish(c_long::from(r))
    }
}

pub(crate) use imp::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn an_interior_nul_path_is_refused_before_any_syscall() {
        let bad = OsString::from_vec(b"/tmp/a\0b".to_vec());
        assert_eq!(
            cpath(&bad).unwrap_err(),
            PathRefused {
                reason: "interior_nul"
            }
        );
    }

    #[test]
    fn a_trailing_nul_is_also_an_interior_nul_for_cstring() {
        let bad = OsString::from_vec(b"/tmp/a\0".to_vec());
        assert!(cpath(&bad).is_err());
    }

    #[test]
    fn ordinary_and_non_utf8_paths_convert() {
        assert_eq!(cpath(OsStr::new("/tmp/x")).unwrap().as_bytes(), b"/tmp/x");
        let raw = OsString::from_vec(vec![b'/', 0xff, 0xfe]);
        assert_eq!(cpath(&raw).unwrap().as_bytes(), &[b'/', 0xff, 0xfe]);
    }

    #[test]
    fn mechanism_names_the_real_path_to_the_kernel() {
        #[cfg(target_os = "linux")]
        assert_eq!(mechanism(), "linux_raw_syscall");
        #[cfg(not(target_os = "linux"))]
        assert_eq!(mechanism(), "libc_wrapper");
    }
}
