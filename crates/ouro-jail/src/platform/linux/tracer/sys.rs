//! The raw kernel interface the observer needs: ptrace, `process_vm_readv`,
//! `waitpid`, `seccomp`.
//!
//! Every `unsafe` block in the tracer that is not the seccomp install lives
//! here, so the rest of the module is ordinary Rust. The request numbers and
//! option bits are spelled out rather than taken from `libc` so that the ABI
//! this module speaks is visible in one place; [`tests`] asserts each one
//! against `libc` so a typo cannot survive a build.

use std::io;

use libc::{c_int, c_uint, c_void, pid_t};

// ------------------------------------------------------------ ptrace ABI

pub const PTRACE_CONT: c_uint = 7;
pub const PTRACE_DETACH: c_uint = 17;
pub const PTRACE_SYSCALL: c_uint = 24;
pub const PTRACE_GETEVENTMSG: c_uint = 0x4201;
pub const PTRACE_SEIZE: c_uint = 0x4206;
pub const PTRACE_LISTEN: c_uint = 0x4208;
/// Not in every `libc` release; kernel 4.3 and later.
pub const PTRACE_GET_SYSCALL_INFO: c_uint = 0x420e;

pub const PTRACE_O_TRACESYSGOOD: u64 = 0x0000_0001;
pub const PTRACE_O_TRACEFORK: u64 = 0x0000_0002;
pub const PTRACE_O_TRACEVFORK: u64 = 0x0000_0004;
pub const PTRACE_O_TRACECLONE: u64 = 0x0000_0008;
pub const PTRACE_O_TRACEEXEC: u64 = 0x0000_0010;
pub const PTRACE_O_TRACEEXIT: u64 = 0x0000_0040;
pub const PTRACE_O_TRACESECCOMP: u64 = 0x0000_0080;
pub const PTRACE_O_EXITKILL: u64 = 0x0010_0000;

/// The option word of the contract: every event the closed set needs, plus
/// `EXITKILL` so a dead supervisor cannot leave a traced tree running.
///
/// It is delivered by `PTRACE_SEIZE` itself rather than by a following
/// `PTRACE_SETOPTIONS`, which the kernel would refuse: every ptrace request
/// other than attach, seize, interrupt and kill needs the tracee stopped, and
/// a seized tracee is not.
pub const SEIZE_OPTIONS: u64 = PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_TRACEEXIT
    | PTRACE_O_TRACESECCOMP
    | PTRACE_O_EXITKILL;

pub const PTRACE_EVENT_FORK: c_int = 1;
pub const PTRACE_EVENT_VFORK: c_int = 2;
pub const PTRACE_EVENT_CLONE: c_int = 3;
pub const PTRACE_EVENT_EXEC: c_int = 4;
pub const PTRACE_EVENT_VFORK_DONE: c_int = 5;
pub const PTRACE_EVENT_EXIT: c_int = 6;
pub const PTRACE_EVENT_SECCOMP: c_int = 7;
pub const PTRACE_EVENT_STOP: c_int = 128;

/// `SIGTRAP | 0x80`: a syscall stop under `PTRACE_O_TRACESYSGOOD`.
pub const SYSCALL_STOP_SIG: c_int = libc::SIGTRAP | 0x80;

/// `struct ptrace_syscall_info.op`.
pub const SYSCALL_INFO_NONE: u8 = 0;
pub const SYSCALL_INFO_ENTRY: u8 = 1;
pub const SYSCALL_INFO_EXIT: u8 = 2;
pub const SYSCALL_INFO_SECCOMP: u8 = 3;

/// The in-kernel restart codes. They are visible to a tracer at a syscall
/// exit stop and never to user space: the kernel re-enters the syscall
/// afterwards, so treating one as a result would double-count the call
/// (jail-v1 §11.2, "Syscall restarts must not create duplicate successes").
pub const ERESTARTSYS: i64 = 512;
pub const ERESTARTNOINTR: i64 = 513;
pub const ERESTARTNOHAND: i64 = 514;
pub const ERESTART_RESTARTBLOCK: i64 = 516;

/// True for the four restart codes, and for nothing else. The range is not
/// contiguous: 515 is `ENOIOCTLCMD`, an ordinary internal failure and not a
/// signal to re-enter the syscall.
#[must_use]
pub fn is_restart(rval: i64) -> bool {
    matches!(
        rval,
        v if v == -ERESTARTSYS
            || v == -ERESTARTNOINTR
            || v == -ERESTARTNOHAND
            || v == -ERESTART_RESTARTBLOCK
    )
}

// ------------------------------------------------------------ seccomp ABI

pub const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// x86_64 marks an x32 syscall by this bit in `nr`.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

pub const BPF_LD_W_ABS: u16 = 0x20;
pub const BPF_JEQ_K: u16 = 0x15;
pub const BPF_JGE_K: u16 = 0x35;
pub const BPF_RET_K: u16 = 0x06;

/// Byte offsets into `struct seccomp_data`.
pub const SECCOMP_DATA_NR: u32 = 0;
pub const SECCOMP_DATA_ARCH: u32 = 4;

// ------------------------------------------------------------ ptrace calls

fn ptrace_raw(
    request: c_uint,
    pid: pid_t,
    addr: *mut c_void,
    data: *mut c_void,
) -> io::Result<libc::c_long> {
    // `ptrace` returns -1 both for an error and for a legitimate -1 result,
    // so errno is cleared first. The observer never uses PEEK requests, where
    // that distinction matters, but clearing costs nothing and keeps the
    // helper honest for every caller.
    // SAFETY: `__errno_location` returns a pointer to this thread's errno,
    // valid for the lifetime of the thread.
    unsafe { *libc::__errno_location() = 0 };
    // SAFETY: a ptrace request with a pid and two machine words. Every caller
    // below passes either a null pointer, an integer encoded as a pointer
    // (which the kernel reads as a value, never dereferences), or a pointer to
    // a live local buffer whose size matches the `addr` argument. The kernel
    // validates `pid`; a wrong one fails with ESRCH rather than acting on
    // another process.
    let rc = unsafe { libc::ptrace(request, pid, addr, data) };
    if rc == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(0) {
            return Err(err);
        }
    }
    Ok(rc)
}

fn as_ptr(value: u64) -> *mut c_void {
    value as usize as *mut c_void
}

/// `PTRACE_SEIZE` with the option word in one call. The tracee is not
/// stopped by this and does not learn it happened.
pub fn seize(pid: pid_t, options: u64) -> io::Result<()> {
    ptrace_raw(PTRACE_SEIZE, pid, std::ptr::null_mut(), as_ptr(options)).map(|_| ())
}

/// Restart a stopped tracee. `signal` is delivered to it; 0 delivers nothing.
pub fn restart(pid: pid_t, request: c_uint, signal: c_int) -> io::Result<()> {
    ptrace_raw(request, pid, std::ptr::null_mut(), as_ptr(signal as u64)).map(|_| ())
}

/// `PTRACE_LISTEN`: leave a group-stopped tracee stopped, as the signal that
/// stopped it intended, while staying its tracer.
pub fn listen(pid: pid_t) -> io::Result<()> {
    ptrace_raw(
        PTRACE_LISTEN,
        pid,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
    .map(|_| ())
}

pub fn detach(pid: pid_t) -> io::Result<()> {
    ptrace_raw(
        PTRACE_DETACH,
        pid,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
    .map(|_| ())
}

pub fn event_msg(pid: pid_t) -> io::Result<u64> {
    let mut msg: libc::c_ulong = 0;
    ptrace_raw(
        PTRACE_GETEVENTMSG,
        pid,
        std::ptr::null_mut(),
        (&raw mut msg).cast::<c_void>(),
    )?;
    Ok(msg as u64)
}

/// The decoded `struct ptrace_syscall_info` of a stopped tracee.
#[derive(Debug, Default, Clone, Copy)]
pub struct SyscallInfo {
    pub op: u8,
    pub arch: u32,
    pub nr: u64,
    pub args: [u64; 6],
    pub rval: i64,
}

/// `struct ptrace_syscall_info` as the kernel lays it out on x86_64:
/// `op` at 0, `arch` at 4, then the union at 24 (`nr` + six args for an
/// entry or seccomp stop, `rval` for an exit stop).
const SYSCALL_INFO_LEN: usize = 88;

pub fn syscall_info(pid: pid_t) -> Option<SyscallInfo> {
    let mut buf = [0u8; SYSCALL_INFO_LEN];
    let n = ptrace_raw(
        PTRACE_GET_SYSCALL_INFO,
        pid,
        as_ptr(buf.len() as u64),
        buf.as_mut_ptr().cast::<c_void>(),
    )
    .ok()?;
    if n <= 0 {
        return None;
    }
    let word = |off: usize| u64::from_ne_bytes(buf[off..off + 8].try_into().unwrap_or([0; 8]));
    let mut info = SyscallInfo {
        op: buf[0],
        arch: u32::from_ne_bytes(buf[4..8].try_into().unwrap_or([0; 4])),
        ..SyscallInfo::default()
    };
    match info.op {
        SYSCALL_INFO_ENTRY | SYSCALL_INFO_SECCOMP => {
            info.nr = word(24);
            for (i, slot) in info.args.iter_mut().enumerate() {
                *slot = word(32 + 8 * i);
            }
        }
        SYSCALL_INFO_EXIT => info.rval = word(24) as i64,
        _ => {}
    }
    Some(info)
}

// ------------------------------------------------------- remote memory

/// Copy at most `out.len()` bytes from `addr` in `pid`.
///
/// Returns the number of bytes copied. A short or zero return is normal: the
/// kernel stops at an unmapped page, and `process_vm_readv` may satisfy fewer
/// bytes than asked for. The caller decides what a short read means; this
/// function never invents bytes.
pub fn read_remote(pid: pid_t, addr: u64, out: &mut [u8]) -> usize {
    if addr == 0 || out.is_empty() {
        return 0;
    }
    let local = libc::iovec {
        iov_base: out.as_mut_ptr().cast::<c_void>(),
        iov_len: out.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as usize as *mut c_void,
        iov_len: out.len(),
    };
    // SAFETY: one local iovec describing `out`, which is live and writable for
    // `out.len()` bytes, and one remote iovec that is only an address and a
    // length in another address space; the kernel validates it and returns
    // EFAULT rather than touching this process's memory. The call needs
    // PTRACE_MODE_ATTACH on `pid`, which the tracer thread holds because it is
    // that process's tracer.
    let n = unsafe { libc::process_vm_readv(pid, &raw const local, 1, &raw const remote, 1, 0) };
    if n <= 0 { 0 } else { n as usize }
}

// ------------------------------------------------------------ wait

#[derive(Debug, Clone, Copy)]
pub enum Wait {
    /// A task changed state. `status` is the raw wait status.
    Status { pid: pid_t, status: c_int },
    /// `WNOHANG` and nothing to report.
    Nothing,
    /// No children and no tracees are left.
    NoChildren,
    /// Interrupted; the caller retries.
    Interrupted,
}

/// `waitpid(-1, ..., __WALL | flags)`: every child of this process and every
/// tracee of this thread, threads included.
pub fn wait_any(flags: c_int) -> Wait {
    let mut status: c_int = 0;
    // SAFETY: `waitpid` writes one `c_int` through the pointer; `status` is a
    // live local. -1 asks for any child, which is the contract's design: the
    // tracer thread owns every wait in the process.
    let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::__WALL | flags) };
    if pid > 0 {
        return Wait::Status { pid, status };
    }
    if pid == 0 {
        return Wait::Nothing;
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ECHILD) => Wait::NoChildren,
        Some(libc::EINTR) => Wait::Interrupted,
        _ => Wait::NoChildren,
    }
}

/// This thread's kernel task id. `TracerPid` in `/proc/<pid>/status` names
/// the tracer *thread*, so confirming a seize needs this and not `getpid`.
pub fn gettid() -> pid_t {
    // SAFETY: `gettid` takes no arguments and cannot fail.
    unsafe { libc::gettid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ABI constants spelled out above must be the ones `libc` knows.
    /// `PTRACE_GET_SYSCALL_INFO` is deliberately absent: it is not in every
    /// `libc` release, which is why this module defines it.
    #[test]
    fn ptrace_constants_match_libc() {
        assert_eq!(u64::from(PTRACE_CONT), libc::PTRACE_CONT as u64);
        assert_eq!(u64::from(PTRACE_DETACH), libc::PTRACE_DETACH as u64);
        assert_eq!(u64::from(PTRACE_SYSCALL), libc::PTRACE_SYSCALL as u64);
        assert_eq!(
            u64::from(PTRACE_GETEVENTMSG),
            libc::PTRACE_GETEVENTMSG as u64
        );
        assert_eq!(u64::from(PTRACE_SEIZE), libc::PTRACE_SEIZE as u64);
        assert_eq!(u64::from(PTRACE_LISTEN), libc::PTRACE_LISTEN as u64);
        assert_eq!(PTRACE_O_TRACESYSGOOD, libc::PTRACE_O_TRACESYSGOOD as u64);
        assert_eq!(PTRACE_O_TRACEFORK, libc::PTRACE_O_TRACEFORK as u64);
        assert_eq!(PTRACE_O_TRACEVFORK, libc::PTRACE_O_TRACEVFORK as u64);
        assert_eq!(PTRACE_O_TRACECLONE, libc::PTRACE_O_TRACECLONE as u64);
        assert_eq!(PTRACE_O_TRACEEXEC, libc::PTRACE_O_TRACEEXEC as u64);
        assert_eq!(PTRACE_O_TRACEEXIT, libc::PTRACE_O_TRACEEXIT as u64);
        assert_eq!(PTRACE_O_TRACESECCOMP, libc::PTRACE_O_TRACESECCOMP as u64);
        assert_eq!(PTRACE_O_EXITKILL, libc::PTRACE_O_EXITKILL as u64);
        assert_eq!(
            i64::from(PTRACE_EVENT_FORK),
            i64::from(libc::PTRACE_EVENT_FORK)
        );
        assert_eq!(
            i64::from(PTRACE_EVENT_VFORK),
            i64::from(libc::PTRACE_EVENT_VFORK)
        );
        assert_eq!(
            i64::from(PTRACE_EVENT_CLONE),
            i64::from(libc::PTRACE_EVENT_CLONE)
        );
        assert_eq!(
            i64::from(PTRACE_EVENT_EXEC),
            i64::from(libc::PTRACE_EVENT_EXEC)
        );
        assert_eq!(
            i64::from(PTRACE_EVENT_VFORK_DONE),
            i64::from(libc::PTRACE_EVENT_VFORK_DONE)
        );
        assert_eq!(
            i64::from(PTRACE_EVENT_EXIT),
            i64::from(libc::PTRACE_EVENT_EXIT)
        );
        assert_eq!(
            i64::from(PTRACE_EVENT_SECCOMP),
            i64::from(libc::PTRACE_EVENT_SECCOMP)
        );
    }

    #[test]
    fn seccomp_and_errno_constants_match_libc() {
        assert_eq!(
            SECCOMP_SET_MODE_FILTER,
            i64::from(libc::SECCOMP_SET_MODE_FILTER)
        );
        assert_eq!(SECCOMP_RET_ALLOW, libc::SECCOMP_RET_ALLOW);
        assert_eq!(SECCOMP_RET_TRACE, libc::SECCOMP_RET_TRACE);
    }

    #[test]
    fn restart_codes_are_exactly_the_four_kernel_values() {
        assert!(is_restart(-512), "-ERESTARTSYS");
        assert!(is_restart(-513), "-ERESTARTNOINTR");
        assert!(is_restart(-514), "-ERESTARTNOHAND");
        assert!(is_restart(-516), "-ERESTART_RESTARTBLOCK");
        assert!(!is_restart(-515), "515 is not a restart code");
        assert!(!is_restart(-517), "beyond the restart range");
        assert!(!is_restart(-1), "-EPERM is an ordinary result");
        assert!(!is_restart(0), "success is not a restart");
        assert!(!is_restart(512), "a positive 512 is a byte count");
    }

    /// The unsafe boundary of `read_remote`: a pid that does not exist, a
    /// null address and an empty buffer must all come back as "no bytes",
    /// never as a fabricated read or a crash.
    #[test]
    fn read_remote_refuses_impossible_inputs() {
        let mut buf = [0xabu8; 64];
        assert_eq!(read_remote(0, 0, &mut buf), 0, "null address");
        assert_eq!(read_remote(-1, 0x1000, &mut buf), 0, "negative pid");
        assert_eq!(
            read_remote(std::process::id() as pid_t, 0x1, &mut buf),
            0,
            "unmapped page"
        );
        assert_eq!(
            read_remote(std::process::id() as pid_t, 0x1000, &mut []),
            0,
            "empty buffer"
        );
        assert_eq!(buf, [0xabu8; 64], "no failing read may touch the buffer");
    }

    /// Reading this process's own memory is the positive control for the
    /// same unsafe boundary.
    #[test]
    fn read_remote_reads_this_process() {
        let source = b"/tmp/observer-precondition\0";
        let mut buf = [0u8; 32];
        let n = read_remote(
            std::process::id() as pid_t,
            source.as_ptr() as u64,
            &mut buf[..source.len()],
        );
        assert_eq!(n, source.len());
        assert_eq!(&buf[..source.len()], source);
    }

    /// The unsafe boundary of the ptrace helpers: a pid we do not trace must
    /// fail with ESRCH and must not be reported as a decoded stop.
    #[test]
    fn ptrace_helpers_refuse_a_process_we_do_not_trace() {
        let me = std::process::id() as pid_t;
        assert!(
            syscall_info(me).is_none(),
            "we are not stopped and not our own tracee"
        );
        let err = event_msg(me).expect_err("not a tracee");
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH), "{err}");
    }

    #[test]
    fn gettid_is_a_task_of_this_process() {
        let tid = gettid();
        assert!(tid > 0);
        assert!(
            std::path::Path::new(&format!("/proc/self/task/{tid}")).exists(),
            "gettid must name a task of this thread group"
        );
    }
}
