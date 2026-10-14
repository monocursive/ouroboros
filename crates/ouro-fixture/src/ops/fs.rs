//! The filesystem modes: the closed-set calls, the calls beside them that
//! name no path (`ftruncate`, `write-mmap`), `chdir` and the `mkdir` race.

use std::ffi::{OsStr, c_char, c_int};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use crate::cli::{
    FsMode, LinkVia, MkdirVia, MknodVia, OpenVia, RenameVia, RmdirVia, SymlinkVia, UnlinkVia,
    parse_mode,
};
use crate::raw::{self, Attempt};
use crate::report::{Emitted, Expect, OpReport, Reporter, path_value};

use super::{Stop, check, close_fd, finish, refuse_path, unavailable};

/// Run one filesystem mode.
pub(crate) fn run(rep: &Reporter, mode: FsMode) -> Result<bool, Stop> {
    match mode {
        FsMode::Open {
            path,
            via,
            create,
            trunc,
            write,
            rdwr,
            mode,
            expect,
        } => {
            let mode = parse_mode(&mode).map_err(Stop::Usage)?;
            // clap refuses `--write` with `--rdwr`.
            let access = match (write, rdwr) {
                (_, true) => Access::ReadWrite,
                (true, false) => Access::Write,
                (false, false) => Access::Read,
            };
            let flags = OpenFlags {
                access,
                create,
                trunc,
            };
            Ok(check(rep, open(&path, via, flags, mode), &expect))
        }
        FsMode::Mkdir {
            path,
            via,
            mode,
            dirfd,
            expect,
        } => {
            let mode = parse_mode(&mode).map_err(Stop::Usage)?;
            if dirfd.is_some() && via != MkdirVia::Mkdirat {
                return Err(Stop::Usage("--dirfd needs --via mkdirat".to_string()));
            }
            let dir = open_dirfd(rep, dirfd.as_deref())?;
            Ok(check(
                rep,
                mkdir(&path, via, mode, raw_fd(dir.as_ref())),
                &expect,
            ))
        }
        FsMode::Rename {
            from,
            to,
            via,
            noreplace,
            dirfd,
            dirfd2,
            expect,
        } => {
            if (dirfd.is_some() || dirfd2.is_some()) && via == RenameVia::Rename {
                return Err(Stop::Usage(
                    "--dirfd and --dirfd2 need --via renameat or renameat2".to_string(),
                ));
            }
            // Owned: the first is closed even when the second cannot open.
            let dir = open_dirfd(rep, dirfd.as_deref())?;
            let dir2 = open_dirfd(rep, dirfd2.as_deref())?;
            let (fd, fd2) = (raw_fd(dir.as_ref()), raw_fd(dir2.as_ref()));
            Ok(check(
                rep,
                rename(&from, &to, via, noreplace, fd, fd2),
                &expect,
            ))
        }
        FsMode::Unlink { path, via, expect } => Ok(check(rep, unlink(&path, via), &expect)),
        FsMode::Rmdir { path, via, expect } => Ok(check(rep, rmdir(&path, via), &expect)),
        FsMode::Link {
            from,
            to,
            via,
            expect,
        } => Ok(check(rep, link(&from, &to, via), &expect)),
        FsMode::Symlink {
            target,
            linkpath,
            via,
            expect,
        } => Ok(check(rep, symlink(&target, &linkpath, via), &expect)),
        FsMode::Mknod {
            path,
            via,
            // `--fifo` only spells out the default; clap refuses it with
            // `--regular`.
            fifo: _,
            regular,
            mode,
            expect,
        } => {
            let kind = if regular {
                NodeKind::Regular
            } else {
                NodeKind::Fifo
            };
            let perm = parse_mode(&mode).map_err(Stop::Usage)?;
            Ok(check(rep, mknod(&path, via, kind, perm), &expect))
        }
        FsMode::Truncate {
            path,
            length,
            expect,
        } => Ok(check(rep, truncate(&path, length), &expect)),
        FsMode::Ftruncate {
            path,
            length,
            expect,
        } => Ok(ftruncate(rep, &path, length, &expect)),
        FsMode::WriteMmap { path } => Ok(write_mmap(rep, &path)),
        FsMode::Chdir { path } => Ok(chdir(rep, &path)),
        FsMode::RaceMkdir { a, b, count } => race_mkdir(rep, &a, &b, count),
    }
}

/// The access an open requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access {
    Read,
    Write,
    ReadWrite,
}

/// What an open asks for besides its path and creation mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenFlags {
    pub(crate) access: Access,
    pub(crate) create: bool,
    pub(crate) trunc: bool,
}

impl OpenFlags {
    /// Read-only, creating and truncating nothing.
    pub(crate) const READ: OpenFlags = OpenFlags {
        access: Access::Read,
        create: false,
        trunc: false,
    };

    fn bits(self) -> c_int {
        let mut flags = match self.access {
            Access::Read => libc::O_RDONLY,
            Access::Write => libc::O_WRONLY,
            Access::ReadWrite => libc::O_RDWR,
        };
        if self.create {
            flags |= libc::O_CREAT;
        }
        if self.trunc {
            flags |= libc::O_TRUNC;
        }
        flags
    }
}

/// Open, and close the descriptor again. Most modes only want the result.
fn open(path: &OsStr, via: OpenVia, flags: OpenFlags, mode: u32) -> Emitted {
    let emitted = open_keep(path, via, flags, mode);
    close_fd(emitted.report.ret);
    emitted
}

/// Open and hand the descriptor back in `report.ret`. The caller closes it.
pub(crate) fn open_keep(path: &OsStr, via: OpenVia, flags: OpenFlags, mode: u32) -> Emitted {
    let name = match via {
        OpenVia::Openat => "openat",
        OpenVia::Open => "open",
        OpenVia::Creat => "creat",
        OpenVia::Openat2 => "openat2",
    };
    let mut report = OpReport::new(name);
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "path", path);
        report.result(-1, None);
        return Emitted::unusable(report);
    }

    let mut flags = flags.bits();
    if via == OpenVia::Creat {
        flags = libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC;
        report.set("implied_flags", true);
    }

    path_value(&mut report.args, "path", path);
    report.set("flags", flags);
    report.set("mode", format!("{mode:o}"));
    report.set("mechanism", raw::mechanism());
    if via != OpenVia::Open && via != OpenVia::Creat {
        report.set("dirfd", "AT_FDCWD");
    }

    let attempt = match via {
        OpenVia::Openat => raw::openat(libc::AT_FDCWD, c.as_ptr(), flags, mode),
        OpenVia::Open => raw::open(c.as_ptr(), flags, mode),
        OpenVia::Creat => raw::creat(c.as_ptr(), mode),
        OpenVia::Openat2 => raw::openat2(libc::AT_FDCWD, c.as_ptr(), flags, mode),
    };
    finish(report, attempt)
}

/// Open DIR read-only as a directory, for a `--dirfd` option, and report
/// the open as its own line: the descriptor is part of what the next call
/// names, so a reader must be able to see where it came from. A read-only
/// open is outside the closed set, so a tracer reports nothing for it.
fn open_dirfd(rep: &Reporter, dir: Option<&OsStr>) -> Result<Option<OwnedFd>, Stop> {
    let Some(dir) = dir else {
        return Ok(None);
    };
    let c = raw::cpath(dir)
        .map_err(|e| Stop::Usage(format!("--dirfd cannot be a path: {}", e.reason)))?;
    let mut report = OpReport::new("openat");
    path_value(&mut report.args, "path", dir);
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    report.set("flags", flags);
    report.set("dirfd", "AT_FDCWD");
    report.set("purpose", "dirfd");
    report.set("mechanism", raw::mechanism());
    let emitted = finish(report, raw::openat(libc::AT_FDCWD, c.as_ptr(), flags, 0));
    rep.emit(&emitted.report);
    if emitted.report.ret < 0 {
        return Err(Stop::Failed(format!(
            "--dirfd {} could not be opened: {:?}",
            dir.to_string_lossy(),
            emitted.report.errno
        )));
    }
    let fd = c_int::try_from(emitted.report.ret).map_err(|_| {
        Stop::Failed(format!(
            "openat returned {}, not a descriptor",
            emitted.report.ret
        ))
    })?;
    // SAFETY: `fd` was just returned by a successful `openat` and nothing
    // else owns it.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// The number of a descriptor the caller keeps open for the call.
fn raw_fd(fd: Option<&OwnedFd>) -> Option<c_int> {
    fd.map(AsRawFd::as_raw_fd)
}

/// The directory a path argument is resolved against: a descriptor the
/// fixture opened, or `AT_FDCWD`.
fn dirfd_arg(report: &mut OpReport, key: &str, fd: Option<c_int>) -> c_int {
    match fd {
        Some(fd) => {
            report.set(key, fd);
            fd
        }
        None => {
            report.set(key, "AT_FDCWD");
            libc::AT_FDCWD
        }
    }
}

fn mkdir(path: &OsStr, via: MkdirVia, mode: u32, dir: Option<c_int>) -> Emitted {
    let name = match via {
        MkdirVia::Mkdir => "mkdir",
        MkdirVia::Mkdirat => "mkdirat",
    };
    let mut report = OpReport::new(name);
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "path", path);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "path", path);
    report.set("mode", format!("{mode:o}"));
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        MkdirVia::Mkdir => raw::mkdir(c.as_ptr(), mode),
        MkdirVia::Mkdirat => {
            let fd = dirfd_arg(&mut report, "dirfd", dir);
            raw::mkdirat(fd, c.as_ptr(), mode)
        }
    };
    finish(report, attempt)
}

fn rename(
    from: &OsStr,
    to: &OsStr,
    via: RenameVia,
    noreplace: bool,
    dir: Option<c_int>,
    dir2: Option<c_int>,
) -> Emitted {
    let name = match via {
        RenameVia::Rename => "rename",
        RenameVia::Renameat => "renameat",
        RenameVia::Renameat2 => "renameat2",
    };
    let mut report = OpReport::new(name);
    let (cf, ct) = match (raw::cpath(from), raw::cpath(to)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) => return refuse_path(report, "from", from, e.reason),
        (_, Err(e)) => return refuse_path(report, "to", to, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "from", from);
        path_value(&mut report.args, "to", to);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "from", from);
    path_value(&mut report.args, "to", to);
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        RenameVia::Rename => raw::rename(cf.as_ptr(), ct.as_ptr()),
        RenameVia::Renameat => {
            let fd = dirfd_arg(&mut report, "dirfd", dir);
            let fd2 = dirfd_arg(&mut report, "dirfd2", dir2);
            raw::renameat(fd, cf.as_ptr(), fd2, ct.as_ptr())
        }
        RenameVia::Renameat2 => {
            let flags = if noreplace { rename_noreplace() } else { 0 };
            let fd = dirfd_arg(&mut report, "dirfd", dir);
            let fd2 = dirfd_arg(&mut report, "dirfd2", dir2);
            report.set("flags", flags);
            raw::renameat2(fd, cf.as_ptr(), fd2, ct.as_ptr(), flags)
        }
    };
    finish(report, attempt)
}

const fn rename_noreplace() -> u32 {
    // RENAME_NOREPLACE, uapi/linux/fs.h. Only reaches the kernel on Linux.
    1
}

fn unlink(path: &OsStr, via: UnlinkVia) -> Emitted {
    let name = match via {
        UnlinkVia::Unlink => "unlink",
        UnlinkVia::Unlinkat => "unlinkat",
    };
    let mut report = OpReport::new(name);
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "path", path);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "path", path);
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        UnlinkVia::Unlink => raw::unlink(c.as_ptr()),
        UnlinkVia::Unlinkat => {
            report.set("dirfd", "AT_FDCWD");
            report.set("flags", 0);
            raw::unlinkat(libc::AT_FDCWD, c.as_ptr(), 0)
        }
    };
    finish(report, attempt)
}

fn rmdir(path: &OsStr, via: RmdirVia) -> Emitted {
    let name = match via {
        RmdirVia::Rmdir => "rmdir",
        RmdirVia::Unlinkat => "unlinkat",
    };
    let mut report = OpReport::new(name);
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "path", path);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "path", path);
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        RmdirVia::Rmdir => raw::rmdir(c.as_ptr()),
        RmdirVia::Unlinkat => {
            report.set("dirfd", "AT_FDCWD");
            report.set("flags", libc::AT_REMOVEDIR);
            raw::unlinkat(libc::AT_FDCWD, c.as_ptr(), libc::AT_REMOVEDIR)
        }
    };
    finish(report, attempt)
}

fn link(from: &OsStr, to: &OsStr, via: LinkVia) -> Emitted {
    let name = match via {
        LinkVia::Link => "link",
        LinkVia::Linkat => "linkat",
    };
    let mut report = OpReport::new(name);
    let (cf, ct) = match (raw::cpath(from), raw::cpath(to)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) => return refuse_path(report, "from", from, e.reason),
        (_, Err(e)) => return refuse_path(report, "to", to, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "from", from);
        path_value(&mut report.args, "to", to);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "from", from);
    path_value(&mut report.args, "to", to);
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        LinkVia::Link => raw::link(cf.as_ptr(), ct.as_ptr()),
        LinkVia::Linkat => {
            report.set("dirfd", "AT_FDCWD");
            report.set("dirfd2", "AT_FDCWD");
            report.set("flags", 0);
            raw::linkat(libc::AT_FDCWD, cf.as_ptr(), libc::AT_FDCWD, ct.as_ptr(), 0)
        }
    };
    finish(report, attempt)
}

fn symlink(target: &OsStr, linkpath: &OsStr, via: SymlinkVia) -> Emitted {
    let name = match via {
        SymlinkVia::Symlink => "symlink",
        SymlinkVia::Symlinkat => "symlinkat",
    };
    let mut report = OpReport::new(name);
    let (ctarget, clink) = match (raw::cpath(target), raw::cpath(linkpath)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) => return refuse_path(report, "target", target, e.reason),
        (_, Err(e)) => return refuse_path(report, "linkpath", linkpath, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "target", target);
        path_value(&mut report.args, "linkpath", linkpath);
        report.result(-1, None);
        return Emitted::unusable(report);
    }
    path_value(&mut report.args, "target", target);
    path_value(&mut report.args, "linkpath", linkpath);
    report.set("mechanism", raw::mechanism());
    let attempt = match via {
        SymlinkVia::Symlink => raw::symlink(ctarget.as_ptr(), clink.as_ptr()),
        SymlinkVia::Symlinkat => {
            report.set("dirfd2", "AT_FDCWD");
            raw::symlinkat(ctarget.as_ptr(), libc::AT_FDCWD, clink.as_ptr())
        }
    };
    finish(report, attempt)
}

/// The `S_IF*` file-type bits, widened once.
///
/// They are `u32` on Linux and `mode_t` (`u16`) on Darwin, so a cast that is
/// necessary on one platform is a lint on the other. Both cfg arms are kept
/// here rather than at every use.
#[cfg(target_os = "linux")]
const fn file_type_bits(kind: NodeKind) -> u32 {
    match kind {
        NodeKind::Regular => libc::S_IFREG,
        NodeKind::Fifo => libc::S_IFIFO,
    }
}

#[cfg(not(target_os = "linux"))]
const fn file_type_bits(kind: NodeKind) -> u32 {
    (match kind {
        NodeKind::Regular => libc::S_IFREG,
        NodeKind::Fifo => libc::S_IFIFO,
    }) as u32
}

/// The `S_IFMT` mask, widened the same way. Only a test needs it.
#[cfg(all(test, target_os = "linux"))]
const fn file_type_mask() -> u32 {
    libc::S_IFMT
}

#[cfg(all(test, not(target_os = "linux")))]
const fn file_type_mask() -> u32 {
    libc::S_IFMT as u32
}

/// The kind of node `mknod` makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeKind {
    Fifo,
    Regular,
}

fn mknod(path: &OsStr, via: MknodVia, kind: NodeKind, perm: u32) -> Emitted {
    let name = match via {
        MknodVia::Mknod => "mknod",
        MknodVia::Mknodat => "mknodat",
    };
    let mut report = OpReport::new(name);
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    if let Some(reason) = unavailable(name) {
        report.set("unsupported", reason);
        path_value(&mut report.args, "path", path);
        report.result(-1, None);
        return Emitted::unusable(report);
    }

    // The file-type bits are part of `mode`, not a separate argument. Only
    // S_IFIFO and S_IFREG are offered: S_IFCHR and S_IFBLK need CAP_MKNOD, and
    // a fixture that always fails would prove nothing.
    let mode = file_type_bits(kind) | (perm & 0o7777);
    let dev: u64 = 0;

    path_value(&mut report.args, "path", path);
    report.set("mode", format!("{mode:o}"));
    report.set("dev", dev);
    report.set(
        "kind",
        match kind {
            NodeKind::Regular => "S_IFREG",
            NodeKind::Fifo => "S_IFIFO",
        },
    );
    report.set("mechanism", raw::mechanism());

    let attempt = match via {
        MknodVia::Mknod => raw::mknod(c.as_ptr(), mode, dev),
        MknodVia::Mknodat => {
            report.set("dirfd", "AT_FDCWD");
            raw::mknodat(libc::AT_FDCWD, c.as_ptr(), mode, dev)
        }
    };
    finish(report, attempt)
}

fn truncate(path: &OsStr, length: i64) -> Emitted {
    let mut report = OpReport::new("truncate");
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => return refuse_path(report, "path", path, e.reason),
    };
    path_value(&mut report.args, "path", path);
    report.set("length", length);
    report.set("mechanism", raw::mechanism());
    finish(report, raw::truncate(c.as_ptr(), length))
}

/// Open the path, then truncate through the descriptor.
///
/// Both lines are emitted: the `openat` that names a path, and the
/// `ftruncate` that names only a descriptor. A tracer that reports paths can
/// attribute the first and not the second, which is the distinction this mode
/// exists to make visible. `--expect` applies to the `ftruncate`.
fn ftruncate(rep: &Reporter, path: &OsStr, length: i64, expect: &Expect) -> bool {
    let opened = open_keep(
        path,
        OpenVia::Openat,
        OpenFlags {
            access: Access::ReadWrite,
            create: false,
            trunc: false,
        },
        0o600,
    );
    rep.emit(&opened.report);
    if opened.unusable || opened.report.ret < 0 {
        return false;
    }
    let fd = opened.report.ret as c_int;

    let mut report = OpReport::new("ftruncate");
    path_value(&mut report.args, "path", path);
    report.set("fd", fd);
    report.set("length", length);
    report.set("mechanism", raw::mechanism());
    report.set("path_named_to_the_kernel", false);
    let emitted = finish(report, raw::ftruncate(fd, length));
    close_fd(i64::from(fd));
    rep.emit(&emitted.report);
    emitted.satisfies(expect)
}

fn write_mmap(rep: &Reporter, path: &OsStr) -> bool {
    const LEN: usize = 4096;
    // One open, one reported line: reopening silently would put a second
    // `openat` in a tracer's view that no report line accounts for.
    let opened = open_keep(
        path,
        OpenVia::Openat,
        OpenFlags {
            access: Access::ReadWrite,
            create: true,
            trunc: true,
        },
        0o600,
    );
    rep.emit(&opened.report);
    if opened.unusable || opened.report.ret < 0 {
        return false;
    }
    let fd = opened.report.ret as c_int;

    let mut ok = true;
    let tr = match raw::ftruncate(fd, LEN as i64) {
        Attempt::Performed { ret, .. } => ret,
        Attempt::Absent(_) => -1,
    };
    let mut r = OpReport::new("ftruncate");
    r.set("len", LEN);
    r.set("closed_set", false);
    r.result(
        tr,
        if tr < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        },
    );
    ok &= tr == 0;
    rep.emit(&r);

    let payload = b"ouro-fixture:write\n";
    // SAFETY: `payload` is live; `fd` is open for writing.
    let wn = unsafe { libc::write(fd, payload.as_ptr().cast::<libc::c_void>(), payload.len()) };
    let mut r = OpReport::new("write");
    r.set("len", payload.len());
    r.set("closed_set", false);
    r.result(
        wn as i64,
        if wn < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        },
    );
    ok &= wn == payload.len() as isize;
    rep.emit(&r);

    // SAFETY: `fd` is an open regular file of at least LEN bytes; the kernel
    // chooses the address and the mapping is unmapped below.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    let mut r = OpReport::new("mmap");
    r.set("len", LEN);
    r.set("closed_set", false);
    if addr == libc::MAP_FAILED {
        r.result(-1, std::io::Error::last_os_error().raw_os_error());
        rep.emit(&r);
        // SAFETY: `fd` is owned here.
        unsafe { libc::close(fd) };
        return false;
    }
    r.result(0, None);
    rep.emit(&r);

    let stored = b"ouro-fixture:mmap\n";
    // SAFETY: the mapping is LEN bytes of writable memory and `stored` is
    // much shorter than LEN.
    unsafe {
        std::ptr::copy_nonoverlapping(stored.as_ptr(), addr.cast::<u8>(), stored.len());
    }
    // SAFETY: `addr`/`LEN` are exactly the mapping created above.
    let sy = unsafe { libc::msync(addr, LEN, libc::MS_SYNC) };
    let mut r = OpReport::new("msync");
    r.set("stored_through_mapping", stored.len());
    r.set("closed_set", false);
    r.result(
        i64::from(sy),
        if sy < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        },
    );
    ok &= sy == 0;
    rep.emit(&r);

    // SAFETY: `addr`/`LEN` are exactly the mapping created above.
    let un = unsafe { libc::munmap(addr, LEN) };
    let mut r = OpReport::new("munmap");
    r.set("closed_set", false);
    r.result(i64::from(un), None);
    ok &= un == 0;
    rep.emit(&r);

    // SAFETY: `fd` is owned here and used nowhere else afterwards.
    unsafe { libc::close(fd) };
    ok
}

fn chdir(rep: &Reporter, path: &OsStr) -> bool {
    let report = OpReport::new("chdir");
    let c = match raw::cpath(path) {
        Ok(c) => c,
        Err(e) => {
            let e = refuse_path(report, "path", path, e.reason);
            rep.emit(&e.report);
            return false;
        }
    };
    let mut report = report;
    path_value(&mut report.args, "path", path);
    report.set("mechanism", raw::mechanism());
    let emitted = finish(report, raw::chdir(c.as_ptr()));
    rep.emit(&emitted.report);
    emitted.satisfies(&Expect::Ok)
}

/// `mkdir` on a buffer whose name a second thread keeps changing.
///
/// The buffer is an array of atomics, so the flipping is defined behaviour
/// in Rust; the kernel reads it as the plain bytes it is. Because A and B
/// differ in one byte only, whatever a tracer snapshots at the entry is
/// literally A or B, and what the kernel then consumes may be the other one.
fn race_mkdir(rep: &Reporter, a: &OsStr, b: &OsStr, count: u32) -> Result<bool, Stop> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    if ab.len() != bb.len() {
        return Err(Stop::Usage(
            "race-mkdir: A and B must have the same length".to_string(),
        ));
    }
    let differing: Vec<usize> = (0..ab.len()).filter(|i| ab[*i] != bb[*i]).collect();
    let [at] = differing.as_slice() else {
        return Err(Stop::Usage(
            "race-mkdir: A and B must differ in exactly one byte".to_string(),
        ));
    };
    let at = *at;
    if ab.contains(&0) || bb.contains(&0) {
        return Err(Stop::Usage(
            "race-mkdir: a path cannot contain NUL".to_string(),
        ));
    }
    let buffer: Arc<Vec<AtomicU8>> = Arc::new(
        ab.iter()
            .copied()
            .chain(std::iter::once(0))
            .map(AtomicU8::new)
            .collect(),
    );
    let stop = Arc::new(AtomicBool::new(false));
    let flipper = {
        let buffer = Arc::clone(&buffer);
        let stop = Arc::clone(&stop);
        let (x, y) = (ab[at], bb[at]);
        std::thread::spawn(move || {
            let mut flips = 0u64;
            while !stop.load(Ordering::Relaxed) {
                buffer[at].store(
                    if flips.is_multiple_of(2) { y } else { x },
                    Ordering::Relaxed,
                );
                flips += 1;
            }
            flips
        })
    };
    let mut all = true;
    for _ in 0..count {
        let mut report = OpReport::new("mkdir");
        path_value(&mut report.args, "path_a", a);
        path_value(&mut report.args, "path_b", b);
        report.set("racing", true);
        report.set("mechanism", raw::mechanism());
        // `AtomicU8` has the size and alignment of `u8`, so the array is the
        // NUL-terminated byte string the kernel reads.
        let ptr = buffer.as_ptr().cast::<c_char>();
        let emitted = finish(report, raw::mkdir(ptr, 0o700));
        all &= !emitted.unusable;
        rep.emit(&emitted.report);
    }
    stop.store(true, Ordering::Relaxed);
    let flips = flipper.join().unwrap_or(0);
    let mut done = OpReport::new("race-done");
    done.set("flips", flips);
    done.result(0, None);
    rep.emit(&done);
    Ok(all)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn a_mknod_mode_carries_the_file_type_bits_with_the_permissions() {
        // `mknod` takes one `mode`; getting the type bits wrong silently
        // creates the wrong kind of node.
        //
        // `mknod` rather than `mknodat` so this runs on both platforms: the
        // mode is computed and reported before the syscall, so a Darwin EPERM
        // does not hide it.
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("f");
        let e = mknod(fifo.as_os_str(), MknodVia::Mknod, NodeKind::Fifo, 0o600);
        if e.unusable {
            // An architecture without the legacy number; it says so and the
            // `unavailable` tests cover that classification.
            assert!(e.report.args.contains_key("unsupported"));
            return;
        }
        let mode = e.report.args.get("mode").unwrap().as_str().unwrap();
        let mode = u32::from_str_radix(mode, 8).unwrap();
        assert_eq!(mode & 0o7777, 0o600);
        assert_eq!(mode & file_type_mask(), file_type_bits(NodeKind::Fifo));
        assert_ne!(
            file_type_bits(NodeKind::Regular),
            file_type_bits(NodeKind::Fifo)
        );
        assert_eq!(e.report.args.get("dev").unwrap(), 0);
        assert_eq!(e.report.args.get("kind").unwrap(), "S_IFIFO");
    }

    #[test]
    fn an_interior_nul_path_never_reaches_a_syscall() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = dir.path().join("boundary").into_os_string().into_vec();
        bytes.extend_from_slice(b"\0ignored");
        let bad = OsString::from_vec(bytes);

        let e = open(
            &bad,
            OpenVia::Openat,
            OpenFlags {
                access: Access::Write,
                create: true,
                trunc: false,
            },
            0o600,
        );
        assert!(e.unusable, "a refused path must satisfy nothing");
        assert_eq!(e.report.args.get("refused").unwrap(), "interior_nul");
        assert_eq!(e.report.ret, -1);
        assert!(e.report.errno.is_none());
        assert!(
            !dir.path().join("boundary").exists(),
            "the truncated path must not have been created"
        );
        assert!(!e.satisfies(&Expect::Ok));
        assert!(!e.satisfies(&Expect::Any));
    }
}
