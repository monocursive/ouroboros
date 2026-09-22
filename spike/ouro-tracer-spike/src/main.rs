//! J0 spike: a purpose-built ptrace tracer for the jail-v1 §11 closed set.
//!
//! Disposable measurement code (jail-v1 §16, J0), not the product observer.
//! Linux x86_64 only. It answers one question: what does a tracer that reads
//! only what the closed set needs cost, with and without seccomp narrowing,
//! next to strace and next to no tracer at all.
//!
//! Usage: ouro-tracer-spike [--narrow] [--out PATH] -- PROGRAM [ARG]...
//!
//! `--narrow` installs a seccomp filter in the child before exec that returns
//! SECCOMP_RET_TRACE for the closed set and allows everything else, so only
//! those calls stop the tracee. Without it every syscall stops twice.
//! Events are written to `--out` as tab-separated lines: pid, operation,
//! primary path (or "-"), return value. A summary goes to stderr.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::time::Instant;

use libc::{c_int, c_uint, c_void, pid_t};

const PTRACE_GET_SYSCALL_INFO: c_uint = 0x420e;
const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const PATH_MAX: usize = 4096;

/// The closed set of jail-v1 §11.2 on x86_64: (nr, name, index of the primary
/// path argument, or 255 when there is none).
const CLOSED_SET: &[(u64, &str, u8)] = &[
    (59, "execve", 0),
    (322, "execveat", 1),
    (2, "open", 0),
    (257, "openat", 1),
    (437, "openat2", 1),
    (85, "creat", 0),
    (82, "rename", 0),
    (264, "renameat", 1),
    (316, "renameat2", 1),
    (87, "unlink", 0),
    (263, "unlinkat", 1),
    (84, "rmdir", 0),
    (83, "mkdir", 0),
    (258, "mkdirat", 1),
    (86, "link", 0),
    (265, "linkat", 1),
    (88, "symlink", 0),
    (266, "symlinkat", 0),
    (42, "connect", 255),
];

fn closed(nr: u64) -> Option<&'static (u64, &'static str, u8)> {
    CLOSED_SET.iter().find(|e| e.0 == nr)
}

fn fail(what: &str) -> ! {
    let err = std::io::Error::last_os_error();
    eprintln!("ouro-tracer-spike: {what}: {err}");
    std::process::exit(1)
}

fn usage() -> ! {
    eprintln!("usage: ouro-tracer-spike [--narrow] [--out PATH] -- PROGRAM [ARG]...");
    std::process::exit(2)
}

// ---------------------------------------------------------------- seccomp

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Classic BPF: if arch is x86_64, return TRACE for closed-set numbers and
/// ALLOW for everything else. Any other arch is allowed (this is a spike).
fn install_narrowing_filter() {
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    let n = CLOSED_SET.len() as u8;
    let mut prog = vec![
        SockFilter { code: LD_W_ABS, jt: 0, jf: 0, k: 4 }, // A = seccomp_data.arch
        SockFilter { code: JEQ_K, jt: 1, jf: 0, k: AUDIT_ARCH_X86_64 },
        SockFilter { code: RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW },
        SockFilter { code: LD_W_ABS, jt: 0, jf: 0, k: 0 }, // A = seccomp_data.nr
    ];
    for (i, (nr, _, _)) in CLOSED_SET.iter().enumerate() {
        // Jump over the remaining comparisons and the ALLOW to the TRACE.
        prog.push(SockFilter { code: JEQ_K, jt: n - i as u8, jf: 0, k: *nr as u32 });
    }
    prog.push(SockFilter { code: RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW });
    prog.push(SockFilter { code: RET_K, jt: 0, jf: 0, k: SECCOMP_RET_TRACE });
    let fprog = SockFprog { len: prog.len() as u16, filter: prog.as_ptr() };
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            fail("prctl(PR_SET_NO_NEW_PRIVS)");
        }
        if libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog as *const SockFprog) != 0 {
            fail("seccomp(SECCOMP_SET_MODE_FILTER)");
        }
    }
}

// ---------------------------------------------------------------- ptrace

#[derive(Default)]
struct SysInfo {
    op: u8, // 1 entry, 2 exit, 3 seccomp
    nr: u64,
    args: [u64; 6],
    rval: i64,
}

fn get_syscall_info(pid: pid_t) -> Option<SysInfo> {
    let mut buf = [0u8; 128];
    let r = unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO,
            pid,
            buf.len() as *mut c_void,
            buf.as_mut_ptr() as *mut c_void,
        )
    };
    if r < 0 {
        return None;
    }
    let at = |o: usize| u64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
    let mut info = SysInfo { op: buf[0], ..Default::default() };
    match info.op {
        1 | 3 => {
            info.nr = at(24);
            for (i, a) in info.args.iter_mut().enumerate() {
                *a = at(32 + 8 * i);
            }
        }
        2 => info.rval = at(24) as i64,
        _ => {}
    }
    Some(info)
}

fn event_msg(pid: pid_t) -> u64 {
    let mut msg: libc::c_ulong = 0;
    unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG,
            pid,
            ptr::null_mut::<c_void>(),
            &mut msg as *mut libc::c_ulong as *mut c_void,
        );
    }
    msg as u64
}

fn restart(pid: pid_t, req: c_uint, sig: c_int) {
    unsafe {
        libc::ptrace(req, pid, ptr::null_mut::<c_void>(), sig as usize as *mut c_void);
    }
}

/// Read a NUL-terminated path from the tracee. One read of PATH_MAX, and if
/// that faults (page boundary into an unmapped page) one page-bounded retry.
fn read_path(pid: pid_t, addr: u64, buf: &mut [u8; PATH_MAX], gaps: &mut u64) -> usize {
    if addr == 0 {
        return 0;
    }
    let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut c_void, iov_len: PATH_MAX };
    let mut remote = libc::iovec { iov_base: addr as usize as *mut c_void, iov_len: PATH_MAX };
    let mut n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        remote.iov_len = PATH_MAX - (addr as usize & (PATH_MAX - 1));
        n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n <= 0 {
            *gaps += 1;
            return 0;
        }
    }
    let n = n as usize;
    buf[..n].iter().position(|&b| b == 0).unwrap_or(n)
}

// ---------------------------------------------------------------- tracer

struct Pending {
    name: &'static str,
    path: Vec<u8>,
}

struct Tracee {
    in_call: Option<Pending>,
    fresh: bool,
}

#[derive(Default)]
struct Stats {
    stops: u64,
    tracees_seen: u64,
    exits: u64,
    execs: u64,
    gaps: u64,
    events: HashMap<&'static str, u64>,
}

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let mut narrow = false;
    let mut out: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].to_str() {
            Some("--narrow") => narrow = true,
            Some("--out") => {
                i += 1;
                out = Some(args.get(i).cloned().unwrap_or_else(|| usage()).into());
            }
            Some("--") => {
                i += 1;
                break;
            }
            _ => usage(),
        }
        i += 1;
    }
    let cmd = &args[i..];
    if cmd.is_empty() {
        usage();
    }
    let cstrs: Vec<CString> = cmd.iter().map(|a| CString::new(a.as_bytes()).unwrap()).collect();
    let mut argv: Vec<*const libc::c_char> = cstrs.iter().map(|c| c.as_ptr()).collect();
    argv.push(ptr::null());

    let mut writer: Box<dyn Write> = match out {
        Some(p) => Box::new(BufWriter::with_capacity(1 << 16, File::create(p).unwrap_or_else(|_| fail("open --out")))),
        None => Box::new(std::io::sink()),
    };

    let start = Instant::now();
    let child = unsafe { libc::fork() };
    if child < 0 {
        fail("fork");
    }
    if child == 0 {
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) != 0 {
                libc::_exit(126);
            }
            if narrow {
                install_narrowing_filter();
            }
            libc::raise(libc::SIGSTOP);
            libc::execvp(argv[0], argv.as_ptr());
            libc::_exit(127);
        }
    }

    let mut status: c_int = 0;
    if unsafe { libc::waitpid(child, &mut status, libc::__WALL) } != child || !libc::WIFSTOPPED(status) {
        fail("initial stop");
    }
    let mut opts = libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEEXIT
        | libc::PTRACE_O_EXITKILL;
    if narrow {
        opts |= libc::PTRACE_O_TRACESECCOMP;
    }
    unsafe {
        if libc::ptrace(libc::PTRACE_SETOPTIONS, child, ptr::null_mut::<c_void>(), opts as usize as *mut c_void) != 0 {
            fail("PTRACE_SETOPTIONS");
        }
    }
    let idle: c_uint = if narrow { libc::PTRACE_CONT } else { libc::PTRACE_SYSCALL };

    let mut tracees: HashMap<pid_t, Tracee> = HashMap::new();
    tracees.insert(child, Tracee { in_call: None, fresh: false });
    let mut stats = Stats { tracees_seen: 1, ..Default::default() };
    let mut pathbuf = [0u8; PATH_MAX];
    let mut root_status: Option<c_int> = None;
    restart(child, idle, 0);

    loop {
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if pid < 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ECHILD) => break,
                Some(libc::EINTR) => continue,
                _ => fail("waitpid"),
            }
        }
        stats.stops += 1;
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            tracees.remove(&pid);
            stats.exits += 1;
            if pid == child {
                root_status = Some(status);
            }
            if tracees.is_empty() {
                break;
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let sig = libc::WSTOPSIG(status);
        let event = (status >> 16) & 0xff;
        let t = tracees.entry(pid).or_insert_with(|| {
            stats.tracees_seen += 1;
            Tracee { in_call: None, fresh: true }
        });
        let mut inject = 0;
        let mut new_child: Option<pid_t> = None;

        if event == libc::PTRACE_EVENT_SECCOMP {
            if let Some(info) = get_syscall_info(pid) {
                if let Some((_, name, pidx)) = closed(info.nr) {
                    let path = if *pidx == 255 {
                        Vec::new()
                    } else {
                        let n = read_path(pid, info.args[*pidx as usize], &mut pathbuf, &mut stats.gaps);
                        pathbuf[..n].to_vec()
                    };
                    t.in_call = Some(Pending { name, path });
                }
            }
        } else if event == libc::PTRACE_EVENT_EXEC {
            stats.execs += 1;
            let _ = writeln!(writer, "{pid}\tproc.exec\t-\ttransition");
        } else if event == libc::PTRACE_EVENT_FORK || event == libc::PTRACE_EVENT_VFORK || event == libc::PTRACE_EVENT_CLONE {
            new_child = Some(event_msg(pid) as pid_t); // inserted below, after the entry borrow ends
        } else if event == libc::PTRACE_EVENT_EXIT {
            let code = event_msg(pid);
            let _ = writeln!(writer, "{pid}\tproc.exit\t-\t{code}");
        } else if event == libc::PTRACE_EVENT_VFORK_DONE {
            // nothing to record
        } else if sig == (libc::SIGTRAP | 0x80) {
            // syscall stop: entry (full mode), or the entry/exit that follow a seccomp stop
            match get_syscall_info(pid) {
                Some(info) if info.op == 1 => {
                    if !narrow {
                        if let Some((_, name, pidx)) = closed(info.nr) {
                            let path = if *pidx == 255 {
                                Vec::new()
                            } else {
                                let n = read_path(pid, info.args[*pidx as usize], &mut pathbuf, &mut stats.gaps);
                                pathbuf[..n].to_vec()
                            };
                            t.in_call = Some(Pending { name, path });
                        }
                    }
                }
                Some(info) if info.op == 2 => {
                    if let Some(p) = t.in_call.take() {
                        *stats.events.entry(p.name).or_insert(0) += 1;
                        let _ = write!(writer, "{pid}\t{}\t", p.name);
                        let _ = writer.write_all(if p.path.is_empty() { b"-" } else { &p.path });
                        let _ = writeln!(writer, "\t{}", info.rval);
                    }
                }
                _ => stats.gaps += 1,
            }
        } else if sig == libc::SIGSTOP && t.fresh {
            t.fresh = false; // the auto-attach stop of a new child
        } else {
            inject = sig; // ordinary signal delivery: forward it
        }
        let req = if t.in_call.is_some() { libc::PTRACE_SYSCALL } else { idle };
        if let Some(np) = new_child {
            tracees.entry(np).or_insert_with(|| {
                stats.tracees_seen += 1;
                Tracee { in_call: None, fresh: true }
            });
        }
        restart(pid, req, inject);
    }

    let elapsed = start.elapsed();
    let _ = writer.flush();
    let mut names: Vec<_> = stats.events.iter().collect();
    names.sort();
    eprintln!(
        "ouro-tracer-spike: mode={} elapsed={:.3}s stops={} tracees={} exits={} exec_transitions={} gaps={} events={:?}",
        if narrow { "narrow" } else { "full" },
        elapsed.as_secs_f64(),
        stats.stops,
        stats.tracees_seen,
        stats.exits,
        stats.execs,
        stats.gaps,
        names
    );
    match root_status {
        Some(s) if libc::WIFEXITED(s) => std::process::exit(libc::WEXITSTATUS(s)),
        Some(s) if libc::WIFSIGNALED(s) => std::process::exit(128 + libc::WTERMSIG(s)),
        _ => std::process::exit(1),
    }
}
