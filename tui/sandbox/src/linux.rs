//! The Linux executor: applies a `Plan` to this process, then becomes the command.
//!
//! There are no policy decisions in here. Everything this module does was decided by
//! `crate::plan`, which is portable and unit-tested; this is the part that has to run on a
//! Linux kernel to mean anything, and it is covered by `tests/linux_enforcement.rs`.
//!
//! # Order, and why each step is where it is
//!
//! ```text
//!  1. record the real uid/gid          (before the user namespace renumbers us)
//!  2. unshare(NEWUSER | NEWNS [| NEWNET])
//!  3. write setgroups / uid_map / gid_map
//!  4. bring loopback up                (only when the network namespace is ours)
//!  5. make / rprivate                  (so nothing below propagates to the host)
//!  6. snapshot /proc/self/mountinfo    (the sweep's "before")
//!  7. apply the mount plan
//!  8. setrlimit
//!  9. drop every capability            (mounts are done; nothing after this needs one)
//! 10. prctl(PR_SET_NO_NEW_PRIVS)       (required by 11 and 12, and kills setuid escalation)
//! 11. landlock_restrict_self
//! 12. seccomp
//! 13. chdir, set the filter env, execvp
//! ```
//!
//! Steps 9 through 12 are ordered by dependency, not by preference: Landlock and seccomp
//! both refuse to install without `no_new_privs` unless the caller holds `CAP_SYS_ADMIN`,
//! and the helper has just given that up on purpose.
//!
//! # Failure is a refusal, never a downgrade
//!
//! Every step returns `Result`, and there is no step whose failure is swallowed into "run
//! it anyway with less containment" — with exactly one documented exception, in
//! `read_only_sweep`, where a single un-remountable mount is tolerated *because Landlock
//! independently denies writes to it*. That exception costs the `EROFS` error text on a
//! path nobody writes to, not the containment, and it is the difference between working on
//! ordinary kernels and refusing to run on them.

use crate::mountinfo;
use crate::plan::{MountOp, NetworkPosture, Plan};
use crate::seccomp;
use std::ffi::{CStr, CString};
use std::io::Write;

/// A failure to *apply* the policy. Never the command's own failure.
#[derive(Debug)]
pub struct Failure(pub String);

impl Failure {
    fn new(what: &str) -> Failure {
        Failure(format!("{what}: {}", std::io::Error::last_os_error()))
    }
}

pub type Result<T> = std::result::Result<T, Failure>;

// ---------------------------------------------------------------------- syscall numbers

// Landlock (Linux 5.13). Named here rather than taken from `libc` because the constants
// arrived in libc later than the kernel and pinning them makes the minimum toolchain a
// property of this file instead of of the lockfile.
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
/// `mount_setattr` (Linux 5.12), which is how a single mount is made read-only without
/// having to reconstruct the flags it already had.
const SYS_MOUNT_SETATTR: libc::c_long = 442;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_long = 1;

const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
const AT_RECURSIVE: libc::c_int = 0x8000;

const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

// ------------------------------------------------------------------- landlock access bits

const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
const FS_REFER: u64 = 1 << 13;
const FS_TRUNCATE: u64 = 1 << 14;
const FS_IOCTL_DEV: u64 = 1 << 15;

/// The rights a read-only hierarchy gets.
fn read_set(abi: i32) -> u64 {
    let mut set = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;
    if abi >= 5 {
        set |= FS_IOCTL_DEV;
    }
    set
}

/// The rights a writable hierarchy gets on top of `read_set`.
fn write_set(abi: i32) -> u64 {
    let mut set = FS_WRITE_FILE
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_SOCK
        | FS_MAKE_FIFO
        | FS_MAKE_BLOCK
        | FS_MAKE_SYM;
    if abi >= 2 {
        // Without REFER in the handled set, the kernel denies every rename and hard link
        // that crosses a directory hierarchy — including ones entirely inside the
        // workspace. Handling it and granting it on the writable roots is what keeps an
        // ordinary `mv` working.
        set |= FS_REFER;
    }
    if abi >= 3 {
        set |= FS_TRUNCATE;
    }
    set
}

/// Everything this helper's ruleset takes responsibility for. Anything not in here is
/// outside Landlock's reach entirely and is left to the mount policy.
fn handled_fs(abi: i32) -> u64 {
    read_set(abi) | write_set(abi)
}

/// The rights a rule on a single **file** may carry.
///
/// A `path_beneath` rule whose parent is not a directory is refused with `EINVAL` if it
/// names a directory-only right — `READ_DIR`, any `MAKE_*`, `REMOVE_*`, `REFER`. So the
/// file grants are built from their own sets rather than by masking the directory ones,
/// which would be a mask somebody would later widen without noticing what it is for.
fn file_read_set(abi: i32) -> u64 {
    let mut set = FS_READ_FILE;
    if abi >= 5 {
        // `isatty` and every `TCGETS` a build script runs against `/dev/null` is an ioctl,
        // and an unhandled-but-denied ioctl answers `EACCES` where the device would have
        // answered `ENOTTY`.
        set |= FS_IOCTL_DEV;
    }
    set
}

fn file_write_set(abi: i32) -> u64 {
    let mut set = file_read_set(abi) | FS_WRITE_FILE;
    if abi >= 3 {
        set |= FS_TRUNCATE;
    }
    set
}

// ----------------------------------------------------------------------------- structures

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

// `struct landlock_path_beneath_attr` is packed in the kernel headers: 8 bytes of access
// plus a 4-byte fd, 12 total. A naturally-aligned Rust struct would be 16 and the kernel
// would reject the size.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `struct ifreq`, spelled out rather than taken from `libc` because the union member
/// names there have moved between releases and this needs only the flags.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16],
    flags: libc::c_short,
    _padding: [u8; 14],
}

// ------------------------------------------------------------------------------ landlock

/// The Landlock ABI this kernel speaks, or `None` if it has no Landlock at all.
pub fn landlock_abi() -> Option<i32> {
    let abi = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };

    if abi > 0 {
        Some(abi as i32)
    } else {
        None
    }
}

/// Builds the ruleset and returns its fd. Applying it is a separate step because it must
/// happen after `no_new_privs`.
fn build_landlock(plan: &Plan, abi: i32) -> Result<libc::c_int> {
    let attr = RulesetAttr {
        handled_access_fs: handled_fs(abi),
        // Deliberately zero: see `plan::NetworkPosture`. Denying TCP here would deny
        // loopback too.
        handled_access_net: 0,
    };

    // Only pass the field the ABI knows about. A kernel at ABI 1..3 rejects the 16-byte
    // form outright.
    let size = if abi >= 4 {
        std::mem::size_of::<RulesetAttr>()
    } else {
        std::mem::size_of::<u64>()
    };

    let fd = unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, &attr, size, 0u32) };
    if fd < 0 {
        return Err(Failure::new("landlock_create_ruleset"));
    }
    let fd = fd as libc::c_int;

    let read = read_set(abi);
    let write = read | write_set(abi);

    // Order does not matter to the kernel — Landlock resolves a path by walking up to the
    // closest rule — but it is applied narrowest-last here so a reader sees the same
    // "writable, except here" shape the plan describes.
    let rules = plan
        .landlock
        .read_roots
        .iter()
        .map(|path| (path, read))
        .chain(plan.landlock.write_roots.iter().map(|path| (path, write)))
        .chain(
            plan.landlock
                .read_only_overrides
                .iter()
                .map(|path| (path, read)),
        )
        // The file grants last, and narrowest of all: a rule on `/dev/null` governs that
        // node and grants nothing else in a `/dev` the builder has no rule for.
        .chain(
            plan.landlock
                .read_files
                .iter()
                .map(|path| (path, file_read_set(abi))),
        )
        .chain(
            plan.landlock
                .write_files
                .iter()
                .map(|path| (path, file_write_set(abi))),
        );

    for (path, access) in rules {
        if let Err(error) = add_landlock_rule(fd, path, access) {
            unsafe { libc::close(fd) };
            return Err(error);
        }
    }

    Ok(fd)
}

fn add_landlock_rule(ruleset: libc::c_int, path: &str, access: u64) -> Result<()> {
    let c_path = CString::new(path)
        .map_err(|_| Failure(format!("path {path:?} contains an interior NUL")))?;

    // O_PATH: the fd names the inode for the rule and is never read through, so a rule can
    // be written for a directory this process could not open for reading.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        // A path in the policy that does not exist on disk gets no rule. That is not a
        // silent downgrade: Landlock's default is deny, so an absent path is *more*
        // restricted by being skipped, not less. The one thing it cannot do is deny the
        // path's future creation by name — see `plan::PreloadFilter`.
        return Ok(());
    }

    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };

    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr,
            0u32,
        )
    };
    unsafe { libc::close(fd) };

    if rc < 0 {
        Err(Failure::new(&format!("landlock_add_rule for {path}")))
    } else {
        Ok(())
    }
}

fn apply_landlock(fd: libc::c_int) -> Result<()> {
    let rc = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0u32) };
    unsafe { libc::close(fd) };

    if rc < 0 {
        Err(Failure::new("landlock_restrict_self"))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------- namespaces

/// Whether this process could create the namespaces the helper needs. Destructive: the
/// caller becomes the owner of a new user namespace. Only `doctor` calls it.
pub fn probe_namespaces() -> (bool, bool) {
    let user_mount = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } == 0;
    let net = user_mount && unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0;
    (user_mount, net)
}

fn enter_namespaces(plan: &Plan) -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let mut flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
    if plan.network == NetworkPosture::Unshare {
        flags |= libc::CLONE_NEWNET;
    }

    if unsafe { libc::unshare(flags) } != 0 {
        return Err(Failure::new(
            "unshare(CLONE_NEWUSER|CLONE_NEWNS): this kernel or container policy does not \
             permit unprivileged user namespaces",
        ));
    }

    // `setgroups` must be denied before `gid_map` can be written by an unprivileged
    // process; the kernel refuses the map otherwise.
    write_proc("/proc/self/setgroups", "deny")?;
    // Identity mapping, not a map to root: a file the command creates in the workspace
    // must be owned by the user who owns the workspace, and mapping to uid 0 would make
    // every artefact root-owned on the host.
    write_proc("/proc/self/uid_map", &format!("{uid} {uid} 1"))?;
    write_proc("/proc/self/gid_map", &format!("{gid} {gid} 1"))?;

    if plan.network == NetworkPosture::Unshare {
        // Non-fatal. A namespace with loopback down is still network-isolated, which is
        // the security property; loopback is a compatibility nicety for build tools that
        // talk to themselves over TCP, and failing the command over it would be a worse
        // trade than running without it.
        let _ = bring_loopback_up();
    }

    Ok(())
}

fn write_proc(path: &str, contents: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| Failure(format!("open {path}: {error}")))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| Failure(format!("write {path}: {error}")))
}

fn bring_loopback_up() -> Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(Failure::new("socket"));
    }

    let mut request = IfReq {
        name: [0; 16],
        flags: 0,
        _padding: [0; 14],
    };
    for (i, byte) in b"lo".iter().enumerate() {
        request.name[i] = *byte as libc::c_char;
    }

    let result = unsafe {
        if libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut request) < 0 {
            Err(Failure::new("ioctl(SIOCGIFFLAGS)"))
        } else {
            request.flags |= libc::IFF_UP as libc::c_short;
            if libc::ioctl(fd, libc::SIOCSIFFLAGS, &request) < 0 {
                Err(Failure::new("ioctl(SIOCSIFFLAGS)"))
            } else {
                Ok(())
            }
        }
    };

    unsafe { libc::close(fd) };
    result
}

// -------------------------------------------------------------------------------- mounts

fn mount(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let c_source = to_c(source)?;
    let c_target = CString::new(target)
        .map_err(|_| Failure(format!("path {target:?} contains an interior NUL")))?;
    let c_fstype = to_c(fstype)?;
    let c_data = to_c(data)?;

    let rc = unsafe {
        libc::mount(
            c_source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            c_target.as_ptr(),
            c_fstype.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            c_data
                .as_ref()
                .map_or(std::ptr::null(), |s| s.as_ptr() as *const libc::c_void),
        )
    };

    if rc != 0 {
        Err(Failure::new(&format!("mount {target}")))
    } else {
        Ok(())
    }
}

fn to_c(value: Option<&str>) -> Result<Option<CString>> {
    match value {
        None => Ok(None),
        Some(value) => CString::new(value)
            .map(Some)
            .map_err(|_| Failure(format!("value {value:?} contains an interior NUL"))),
    }
}

/// Makes one mount read-only, preferring `mount_setattr` and falling back to a bind
/// remount on kernels that lack it.
///
/// The fallback matters less than it looks: `mount_setattr` landed in 5.12 and Landlock in
/// 5.13, and this helper refuses to run without Landlock, so the fallback is only ever
/// reached if a seccomp policy above this process has removed the newer call.
fn set_read_only(target: &str) -> Result<()> {
    let c_target = CString::new(target)
        .map_err(|_| Failure(format!("path {target:?} contains an interior NUL")))?;

    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };

    let rc = unsafe {
        libc::syscall(
            SYS_MOUNT_SETATTR,
            libc::AT_FDCWD,
            c_target.as_ptr(),
            0 as libc::c_int,
            &attr,
            std::mem::size_of::<MountAttr>(),
        )
    };

    if rc == 0 {
        return Ok(());
    }

    mount(
        None,
        target,
        None,
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
        None,
    )
}

fn apply_mounts(plan: &Plan, snapshot: &[mountinfo::Mount]) -> Result<()> {
    for op in &plan.mounts {
        match op {
            MountOp::BindWritable { path } => {
                // MS_REC so a workspace containing its own mounts keeps them. The source
                // is still pristine at this point, which is the entire reason this step
                // comes before the sweep.
                mount(Some(path), path, None, libc::MS_BIND | libc::MS_REC, None)?;
            }

            MountOp::Tmpfs { path } => {
                mount(
                    Some("tmpfs"),
                    path,
                    Some("tmpfs"),
                    libc::MS_NOSUID | libc::MS_NODEV,
                    Some("mode=0700"),
                )?;
            }

            MountOp::SealedTmpfs { path } => {
                // Fresh first — which is what takes the host's shared segments out of the
                // namespace — and read-only immediately after, so nothing can be put in
                // their place either. `0555` rather than tmpfs's usual `1777`: a build has
                // no business creating anything here, and the mount flag already says so.
                mount(
                    Some("tmpfs"),
                    path,
                    Some("tmpfs"),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    Some("mode=0555"),
                )?;
                set_read_only(path)?;
            }

            MountOp::ReadOnlySweep { keep_writable } => {
                read_only_sweep(snapshot, keep_writable)?;
            }

            MountOp::BindReadOnly { path, .. } => {
                mount(Some(path), path, None, libc::MS_BIND | libc::MS_REC, None)?;
                set_read_only_recursive(path)?;
            }
        }
    }

    Ok(())
}

/// A read-only bind must cover its submounts too, or a `.git` that happens to be a mount
/// point of its own would be writable through the bind that was supposed to seal it.
fn set_read_only_recursive(target: &str) -> Result<()> {
    let c_target = CString::new(target)
        .map_err(|_| Failure(format!("path {target:?} contains an interior NUL")))?;

    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };

    let rc = unsafe {
        libc::syscall(
            SYS_MOUNT_SETATTR,
            libc::AT_FDCWD,
            c_target.as_ptr(),
            AT_RECURSIVE,
            &attr,
            std::mem::size_of::<MountAttr>(),
        )
    };

    if rc == 0 {
        Ok(())
    } else {
        set_read_only(target)
    }
}

/// Makes every mount that existed before this plan started read-only.
///
/// The one place in this file where a failure is not a refusal, and the reason is
/// specific: `run` has already established that this kernel has Landlock, and the Landlock
/// domain denies writes to these paths independently of whether the mount flag took. So a
/// mount that refuses to be remounted — an autofs, something an enclosing container
/// locked — costs the `EROFS` *error text* on a path the policy does not permit writes to
/// anyway, not the containment.
///
/// `/` is the exception, because if the root filesystem stayed writable the policy's
/// central claim is false and no amount of Landlock makes the refusal legible.
fn read_only_sweep(snapshot: &[mountinfo::Mount], keep_writable: &[String]) -> Result<()> {
    let targets = mountinfo::sweep_targets(snapshot, keep_writable);

    let unswept: Vec<&String> = targets
        .iter()
        .filter(|target| set_read_only(target).is_err())
        .collect();

    if unswept.iter().any(|path| *path == "/") {
        return Err(Failure(
            "could not make / read-only in the mount namespace".to_string(),
        ));
    }

    Ok(())
}

// ----------------------------------------------------------------------- limits and caps

fn apply_limits(plan: &Plan) -> Result<()> {
    let limits = &plan.limits;
    lower(libc::RLIMIT_CORE, Some(limits.core_bytes))?;
    lower(libc::RLIMIT_NPROC, limits.max_processes)?;
    lower(libc::RLIMIT_FSIZE, limits.max_file_bytes)?;
    lower(libc::RLIMIT_CPU, limits.cpu_seconds)?;
    Ok(())
}

/// Sets a limit to the requested value, or leaves it alone if it is already lower.
///
/// Never raises. A request that asked for more than the daemon already permits would
/// otherwise be a way to widen the resource envelope through the sandbox, which is
/// precisely backwards.
fn lower(resource: libc::__rlimit_resource_t, requested: Option<u64>) -> Result<()> {
    let Some(requested) = requested else {
        return Ok(());
    };

    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(resource, &mut current) } != 0 {
        return Err(Failure::new("getrlimit"));
    }

    let ceiling = if current.rlim_max == libc::RLIM_INFINITY {
        requested
    } else {
        requested.min(current.rlim_max)
    };

    let next = libc::rlimit {
        rlim_cur: ceiling,
        rlim_max: ceiling,
    };

    if unsafe { libc::setrlimit(resource, &next) } != 0 {
        return Err(Failure::new("setrlimit"));
    }

    Ok(())
}

/// Drops every capability this process holds in its new user namespace.
///
/// It has a full set there simply for having created it, and it needed `CAP_SYS_ADMIN` to
/// mount. After this point it needs nothing, and holding `CAP_SYS_ADMIN` would mean the
/// command could remount its way out of the policy that was just applied.
fn drop_capabilities() -> Result<()> {
    // The bounding set first: this is what an `execve` of a file with capabilities could
    // otherwise pick back up.
    for capability in 0..=63 {
        // EINVAL for a capability this kernel does not define is expected and not an error.
        unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability as libc::c_ulong, 0, 0, 0) };
    }

    unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };

    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData::default(); 2];

    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0 {
        return Err(Failure::new("capset"));
    }

    Ok(())
}

fn set_no_new_privs() -> Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        Err(Failure::new("prctl(PR_SET_NO_NEW_PRIVS)"))
    } else {
        Ok(())
    }
}

// ------------------------------------------------------------------------------- seccomp

/// The syscalls the belt refuses. See `crate::seccomp` for the reasoning.
///
/// Taken from `libc::SYS_*` so the numbers are the ones for the architecture this binary
/// was actually built for. Anything absent from a given libc target simply is not in the
/// list on that target.
fn denied_syscalls() -> Vec<u32> {
    let mut denied: Vec<libc::c_long> = vec![
        // Undoing the mount policy.
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_mount_setattr,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        // Getting a fresh capability set to try again with.
        libc::SYS_setns,
        libc::SYS_unshare,
        // Kernel text and kernel-side programs.
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        // The host's keyring.
        libc::SYS_add_key,
        libc::SYS_keyctl,
        libc::SYS_request_key,
        // Machine-wide state.
        libc::SYS_acct,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_syslog,
        libc::SYS_quotactl,
    ];

    denied.sort_unstable();
    denied.dedup();
    denied.into_iter().map(|nr| nr as u32).collect()
}

fn apply_seccomp() -> Result<()> {
    if !seccomp::ARCH_KNOWN {
        // A filter with the wrong architecture token matches nothing and allows
        // everything, which is worse than no filter because it looks like one.
        return Err(Failure(
            "no AUDIT_ARCH token for this architecture; refusing to install a seccomp \
             filter that would silently allow everything"
                .to_string(),
        ));
    }

    let guard_x32 = cfg!(target_arch = "x86_64");
    let program = seccomp::assemble(&denied_syscalls(), seccomp::NATIVE_AUDIT_ARCH, guard_x32);

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const seccomp::Instruction,
    }

    let fprog = SockFprog {
        len: program.len() as u16,
        filter: program.as_ptr(),
    };

    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            &fprog as *const SockFprog,
            0,
            0,
        )
    };

    if rc != 0 {
        Err(Failure::new("prctl(PR_SET_SECCOMP)"))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------------- exec

/// Applies the whole plan and replaces this process with `target`.
///
/// Only returns on failure — and a failure here is always a failure to *apply the policy*,
/// never the command's own, which is why the caller reports it with the helper's name in
/// front and an exit status the command could not have produced.
pub fn run(plan: &Plan, target: &[String]) -> Result<std::convert::Infallible> {
    let abi = landlock_abi().ok_or_else(|| {
        Failure(
            "this kernel has no Landlock (needs 5.13 or newer); refusing to run, because \
             the daemon selects this helper only where Landlock can enforce the policy"
                .to_string(),
        )
    })?;

    enter_namespaces(plan)?;

    // Nothing below this line may propagate to the host's mount namespace.
    mount(None, "/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;

    let snapshot = std::fs::read_to_string("/proc/self/mountinfo")
        .map(|contents| mountinfo::parse(&contents))
        .map_err(|error| Failure(format!("read /proc/self/mountinfo: {error}")))?;

    apply_mounts(plan, &snapshot)?;
    apply_limits(plan)?;

    // The ruleset is built before capabilities go, only because a build failure should be
    // reported while this process can still describe itself clearly.
    let ruleset = build_landlock(plan, abi)?;

    drop_capabilities()?;
    set_no_new_privs()?;
    apply_landlock(ruleset)?;
    apply_seccomp()?;

    if let Some(cwd) = &plan.cwd {
        let c_cwd = CString::new(cwd.as_str())
            .map_err(|_| Failure(format!("cwd {cwd:?} contains an interior NUL")))?;
        if unsafe { libc::chdir(c_cwd.as_ptr()) } != 0 {
            return Err(Failure::new(&format!("chdir {cwd}")));
        }
    }

    if let Some(preload) = &plan.preload {
        set_env("LD_PRELOAD", &preload.library)?;
        set_env("OUROBOROS_FS_DENY", &preload.denied_names.join(":"))?;
    }

    let program = CString::new(target[0].as_str())
        .map_err(|_| Failure(format!("program {:?} contains an interior NUL", target[0])))?;
    let argv: Vec<CString> = target
        .iter()
        .map(|arg| {
            CString::new(arg.as_str())
                .map_err(|_| Failure(format!("argument {arg:?} contains an interior NUL")))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut pointers: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    pointers.push(std::ptr::null());

    unsafe { libc::execvp(program.as_ptr(), pointers.as_ptr()) };

    Err(Failure::new(&format!("exec {}", target[0])))
}

fn set_env(name: &str, value: &str) -> Result<()> {
    let c_name = CString::new(name).map_err(|_| Failure("bad env name".to_string()))?;
    let c_value = CString::new(value)
        .map_err(|_| Failure(format!("env {name} value contains an interior NUL")))?;

    if unsafe { libc::setenv(c_name.as_ptr(), c_value.as_ptr(), 1) } != 0 {
        Err(Failure::new(&format!("setenv {name}")))
    } else {
        Ok(())
    }
}

/// The kernel release string, for `doctor`.
///
/// Read through `CStr` rather than by mapping the array: `libc::c_char` is `i8` on x86-64
/// and `u8` on aarch64, so any explicit cast is either necessary or a lint failure
/// depending on which of the two this is built for.
pub fn kernel_release() -> String {
    let mut buffer: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut buffer) } != 0 {
        return "unknown".to_string();
    }

    // Safe: `uname` filled the array and NUL-terminates every field.
    let release = unsafe { CStr::from_ptr(buffer.release.as_ptr()) };
    release.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ABI-degradation path, which the container these tests usually run in cannot
    // otherwise exercise: OrbStack reports Landlock ABI 8, while Ubuntu 24.04 (kernel 6.8,
    // and so GitHub's runners) reports ABI 4. A ruleset naming an access right its kernel
    // does not know is rejected with EINVAL, so getting this masking wrong does not weaken
    // the sandbox — it stops the helper working at all on exactly the kernels most likely
    // to run it.
    #[test]
    fn the_handled_access_set_never_names_a_right_older_kernels_lack() {
        // ABI 1: the original thirteen rights, bits 0..=12.
        assert_eq!(handled_fs(1) & !0x1fff, 0, "{:#x}", handled_fs(1));
        // REFER arrives at 2, TRUNCATE at 3, IOCTL_DEV at 5.
        assert_eq!(handled_fs(1) & FS_REFER, 0);
        assert_eq!(handled_fs(2) & FS_REFER, FS_REFER);
        assert_eq!(handled_fs(2) & FS_TRUNCATE, 0);
        assert_eq!(handled_fs(3) & FS_TRUNCATE, FS_TRUNCATE);
        assert_eq!(handled_fs(4) & FS_IOCTL_DEV, 0);
        assert_eq!(handled_fs(5) & FS_IOCTL_DEV, FS_IOCTL_DEV);
    }

    #[test]
    fn every_abi_grants_reads_and_the_write_set_is_strictly_additional() {
        for abi in 1..=8 {
            let read = read_set(abi);
            let write = write_set(abi);

            // Reads must work on every ABI, or `/` becomes unreadable and nothing runs.
            assert_eq!(read & FS_READ_FILE, FS_READ_FILE, "abi {abi}");
            assert_eq!(read & FS_READ_DIR, FS_READ_DIR, "abi {abi}");
            assert_eq!(read & FS_EXECUTE, FS_EXECUTE, "abi {abi}");

            // The read set is what a protected path gets. A write right leaking into it
            // would open the `.git` fence on every kernel at once.
            assert_eq!(read & FS_WRITE_FILE, 0, "abi {abi}");
            assert_eq!(read & FS_MAKE_DIR, 0, "abi {abi}");
            assert_eq!(read & FS_REMOVE_FILE, 0, "abi {abi}");

            assert_eq!(write & FS_WRITE_FILE, FS_WRITE_FILE, "abi {abi}");
            assert_eq!(handled_fs(abi), read | write, "abi {abi}");
        }
    }

    #[test]
    fn the_seccomp_denylist_is_sorted_deduplicated_and_covers_the_mount_api() {
        let denied = denied_syscalls();
        let mut sorted = denied.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(denied, sorted, "the assembler assumes a clean list");

        for (name, nr) in [
            ("mount", libc::SYS_mount),
            ("umount2", libc::SYS_umount2),
            ("pivot_root", libc::SYS_pivot_root),
            ("setns", libc::SYS_setns),
            ("unshare", libc::SYS_unshare),
            ("move_mount", libc::SYS_move_mount),
        ] {
            assert!(denied.contains(&(nr as u32)), "{name} is not on the belt");
        }

        // `ptrace` is deliberately absent: debugging inside the sandbox is legitimate, and
        // Landlock already confines ptrace to within the domain.
        assert!(!denied.contains(&(libc::SYS_ptrace as u32)));
    }

    // The arithmetic above is checked against itself; this checks it against a kernel.
    // For every ABI level at or below this machine's, build the ruleset exactly as
    // `build_landlock` would — same rights, same struct size — and require the kernel to
    // accept it. A newer kernel accepts an older subset, so an ABI-8 machine can still
    // prove that the ABI-4 shape (16-byte attr, no IOCTL_DEV) is one the kernel takes.
    //
    // This is as close to an ABI-4 kernel as this suite gets, and it is worth saying that
    // it is not the same thing: what is proven is the request, not a 6.8 kernel's
    // response to it.
    #[test]
    fn every_masked_ruleset_this_helper_would_build_is_accepted_by_this_kernel() {
        let Some(abi) = landlock_abi() else {
            eprintln!("SKIPPED: no Landlock on this kernel");
            return;
        };

        for target in 1..=abi {
            let attr = RulesetAttr {
                handled_access_fs: handled_fs(target),
                handled_access_net: 0,
            };
            let size = if target >= 4 {
                std::mem::size_of::<RulesetAttr>()
            } else {
                std::mem::size_of::<u64>()
            };

            let fd = unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, &attr, size, 0u32) };
            assert!(
                fd >= 0,
                "abi {target}: kernel rejected the ruleset this helper would build: {}",
                std::io::Error::last_os_error()
            );
            unsafe { libc::close(fd as libc::c_int) };
        }
    }

    #[test]
    fn the_kernel_structs_are_the_sizes_the_kernel_checks() {
        // `landlock_path_beneath_attr` is packed: 8 bytes of access plus a 4-byte fd. A
        // naturally-aligned version is 16 and the kernel rejects the size outright.
        assert_eq!(std::mem::size_of::<PathBeneathAttr>(), 12);
        assert_eq!(std::mem::size_of::<MountAttr>(), 32);
    }
}
