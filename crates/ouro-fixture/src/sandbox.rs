//! `sandbox-exec`: an unprivileged inner sandbox, the way a vendor agent's
//! own sandbox wraps the tool commands it runs.
//!
//! In order, each step reported on its own line and each one required:
//!
//! 1. `prctl(PR_SET_NO_NEW_PRIVS, 1)`, which both Landlock and seccomp need
//!    without CAP_SYS_ADMIN.
//! 2. Landlock, when a tree or `--landlock-deny-tcp` is given: probe the ABI,
//!    create a ruleset handling every filesystem right this ABI knows (when a
//!    tree is granted) and TCP connect (when asked, ABI 4 and later), add one
//!    `path_beneath` rule per tree, and restrict this process.
//! 3. seccomp, when a syscall is named: a filter that checks the
//!    architecture (x86_64, x32 numbers refused), returns `EPERM` for the
//!    named numbers and allows everything else.
//! 4. `execve` of ARGV. Nothing is reported on success: the image is gone.
//!
//! A step that fails stops the mode before the exec: running the command
//! without the sandbox it asked for would be the silent degradation the
//! product forbids. So does a request the kernel cannot honour (TCP rules on
//! ABI < 4, the x86_64 table on another architecture): it is refused before
//! the first step, never approximated.
//!
//! The seccomp program is built by a pure function ([`seccomp_program`]) and
//! proved by a small interpreter in the tests, on every platform.

use std::ffi::OsString;

use crate::cli::ExecVia;
use crate::ops::{Session, Usage, argv_report, do_exec, finish, image};
use crate::report::{Emitted, Expect, OpReport, Reporter};

// ------------------------------------------------------------- the syscalls

/// x86_64 syscall numbers the filter can name, from
/// `arch/x86/entry/syscalls/syscall_64.tbl`. Checked against `libc` by a
/// test on Linux x86_64.
pub const X86_64_SYSCALLS: &[(&str, u32)] = &[
    ("read", 0),
    ("write", 1),
    ("open", 2),
    ("close", 3),
    ("stat", 4),
    ("fstat", 5),
    ("lstat", 6),
    ("poll", 7),
    ("mmap", 9),
    ("mprotect", 10),
    ("ioctl", 16),
    ("pipe", 22),
    ("dup", 32),
    ("dup2", 33),
    ("getpid", 39),
    ("socket", 41),
    ("connect", 42),
    ("accept", 43),
    ("sendto", 44),
    ("recvfrom", 45),
    ("sendmsg", 46),
    ("recvmsg", 47),
    ("shutdown", 48),
    ("bind", 49),
    ("listen", 50),
    ("socketpair", 53),
    ("setsockopt", 54),
    ("clone", 56),
    ("fork", 57),
    ("vfork", 58),
    ("execve", 59),
    ("kill", 62),
    ("uname", 63),
    ("fcntl", 72),
    ("flock", 73),
    ("truncate", 76),
    ("ftruncate", 77),
    ("getcwd", 79),
    ("chdir", 80),
    ("fchdir", 81),
    ("rename", 82),
    ("mkdir", 83),
    ("rmdir", 84),
    ("creat", 85),
    ("link", 86),
    ("unlink", 87),
    ("symlink", 88),
    ("readlink", 89),
    ("chmod", 90),
    ("fchmod", 91),
    ("chown", 92),
    ("fchown", 93),
    ("lchown", 94),
    ("ptrace", 101),
    ("setuid", 105),
    ("setgid", 106),
    ("setsid", 112),
    ("mknod", 133),
    ("personality", 135),
    ("pivot_root", 155),
    ("prctl", 157),
    ("chroot", 161),
    ("mount", 165),
    ("umount2", 166),
    ("sethostname", 170),
    ("setdomainname", 171),
    ("gettid", 186),
    ("tkill", 200),
    ("add_key", 248),
    ("request_key", 249),
    ("keyctl", 250),
    ("openat", 257),
    ("mkdirat", 258),
    ("mknodat", 259),
    ("fchownat", 260),
    ("newfstatat", 262),
    ("unlinkat", 263),
    ("renameat", 264),
    ("linkat", 265),
    ("symlinkat", 266),
    ("readlinkat", 267),
    ("fchmodat", 268),
    ("faccessat", 269),
    ("unshare", 272),
    ("accept4", 288),
    ("dup3", 292),
    ("pipe2", 293),
    ("perf_event_open", 298),
    ("name_to_handle_at", 303),
    ("open_by_handle_at", 304),
    ("setns", 308),
    ("process_vm_readv", 310),
    ("process_vm_writev", 311),
    ("renameat2", 316),
    ("seccomp", 317),
    ("memfd_create", 319),
    ("bpf", 321),
    ("execveat", 322),
    ("userfaultfd", 323),
    ("statx", 332),
    ("pidfd_send_signal", 424),
    ("io_uring_setup", 425),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
    ("open_tree", 428),
    ("move_mount", 429),
    ("fsopen", 430),
    ("fsconfig", 431),
    ("fsmount", 432),
    ("fspick", 433),
    ("pidfd_open", 434),
    ("clone3", 435),
    ("openat2", 437),
    ("pidfd_getfd", 438),
    ("faccessat2", 439),
    ("mount_setattr", 442),
    ("landlock_create_ruleset", 444),
    ("landlock_add_rule", 445),
    ("landlock_restrict_self", 446),
];

/// The most syscalls one filter may name. Two instructions each keeps the
/// program far inside `BPF_MAXINSNS` and every jump offset at 0 or 1.
pub const MAX_SECCOMP_SYSCALLS: usize = 256;

/// Resolve names (or decimal numbers below 1024) to x86_64 numbers,
/// deduplicated in first-seen order.
pub fn resolve_syscalls(names: &[String]) -> Result<Vec<(String, u32)>, Usage> {
    let mut out: Vec<(String, u32)> = Vec::new();
    for n in names {
        let nr = if let Ok(nr) = n.parse::<u32>() {
            if nr >= 1024 {
                return Err(format!("syscall number {nr} is out of range (0..1024)"));
            }
            nr
        } else {
            X86_64_SYSCALLS
                .iter()
                .find(|(name, _)| name == n)
                .map(|(_, nr)| *nr)
                .ok_or_else(|| {
                    format!(
                        "unknown syscall `{n}`: name one of the fixture's x86_64 table or give a number"
                    )
                })?
        };
        if !out.iter().any(|(_, seen)| *seen == nr) {
            out.push((n.clone(), nr));
        }
    }
    if out.len() > MAX_SECCOMP_SYSCALLS {
        return Err(format!(
            "{} syscalls named; the fixture's filter takes at most {MAX_SECCOMP_SYSCALLS}",
            out.len()
        ));
    }
    Ok(out)
}

// ----------------------------------------------------------- seccomp program

/// One classic-BPF instruction, laid out as `struct sock_filter`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// `BPF_LD | BPF_W | BPF_ABS`.
const LD_W_ABS: u16 = 0x20;
/// `BPF_JMP | BPF_JEQ | BPF_K`.
const JEQ_K: u16 = 0x15;
/// `BPF_JMP | BPF_JSET | BPF_K`.
const JSET_K: u16 = 0x45;
/// `BPF_RET | BPF_K`.
const RET_K: u16 = 0x06;

/// `AUDIT_ARCH_X86_64`: EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE.
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// Set in the syscall number of an x32 call.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const RET_ALLOW: u32 = 0x7FFF_0000;
/// `offsetof(struct seccomp_data, nr)` and `arch`.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const EPERM: u32 = 1;

const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

/// The filter: wrong architecture or an x32 number kills the process, a
/// named number returns `EPERM`, everything else is allowed.
#[must_use]
pub fn seccomp_program(numbers: &[u32]) -> Vec<Insn> {
    let mut p = vec![
        insn(LD_W_ABS, 0, 0, OFF_ARCH),
        insn(JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        insn(RET_K, 0, 0, RET_KILL_PROCESS),
        insn(LD_W_ABS, 0, 0, OFF_NR),
        insn(JSET_K, 0, 1, X32_SYSCALL_BIT),
        insn(RET_K, 0, 0, RET_KILL_PROCESS),
    ];
    for nr in numbers {
        p.push(insn(JEQ_K, 0, 1, *nr));
        p.push(insn(RET_K, 0, 0, RET_ERRNO | EPERM));
    }
    p.push(insn(RET_K, 0, 0, RET_ALLOW));
    p
}

/// Run a program over one `(arch, nr)` the way the kernel would, for the
/// tests. Only the opcodes [`seccomp_program`] emits are understood; any
/// other, a jump out of range or falling off the end panics.
#[must_use]
pub fn interpret(program: &[Insn], arch: u32, nr: u32) -> u32 {
    let mut acc = 0u32;
    let mut pc = 0usize;
    loop {
        let i = program[pc];
        match i.code {
            LD_W_ABS => {
                acc = match i.k {
                    OFF_NR => nr,
                    OFF_ARCH => arch,
                    other => panic!("load from unexpected offset {other}"),
                };
                pc += 1;
            }
            JEQ_K | JSET_K => {
                let taken = if i.code == JEQ_K {
                    acc == i.k
                } else {
                    acc & i.k != 0
                };
                pc += 1 + usize::from(if taken { i.jt } else { i.jf });
            }
            RET_K => return i.k,
            other => panic!("unexpected opcode {other:#x}"),
        }
    }
}

// ------------------------------------------------------------------ Landlock

/// `struct landlock_ruleset_attr` (ABI 6 layout; shorter kernels accept it
/// because the trailing fields they do not know are zero).
#[repr(C)]
#[derive(Default)]
pub struct RulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub scoped: u64,
}

/// `struct landlock_path_beneath_attr`, which the kernel declares packed:
/// 12 bytes, not 16.
#[repr(C, packed)]
pub struct PathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
pub const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;
pub const ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

/// Every filesystem right Landlock ABI `abi` knows: 13 in ABI 1, `REFER` from
/// 2, `TRUNCATE` from 3, `IOCTL_DEV` from 5. Nothing is claimed for an ABI
/// this table has not seen beyond the rights ABI 5 defined.
#[must_use]
pub const fn fs_rights(abi: i64) -> u64 {
    match abi {
        i64::MIN..=0 => 0,
        1 => (1 << 13) - 1,
        2 => (1 << 14) - 1,
        3 | 4 => (1 << 15) - 1,
        _ => (1 << 16) - 1,
    }
}

/// The read-only grant: execute, read files, list directories.
pub const RO_RIGHTS: u64 = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR;

// ---------------------------------------------------------------------- mode

/// The parsed request.
pub(crate) struct Request<'a> {
    pub(crate) rw: &'a [OsString],
    pub(crate) ro: &'a [OsString],
    pub(crate) deny_tcp: bool,
    pub(crate) seccomp: &'a [String],
    pub(crate) argv: &'a [OsString],
}

fn refuse(rep: &Reporter, op: &str, key: &str, why: String) -> bool {
    let mut report = OpReport::new(op);
    report.set(key, why);
    report.result(-1, None);
    let e = Emitted::unusable(report);
    rep.emit(&e.report);
    false
}

pub(crate) fn sandbox_exec(
    session: &Session<'_>,
    rep: &Reporter,
    req: &Request<'_>,
) -> Result<bool, Usage> {
    // Everything that can be refused is refused before the first step.
    let syscalls = resolve_syscalls(req.seccomp)?;
    let img = image(req.argv)?;
    if !cfg!(target_os = "linux") {
        return Ok(refuse(
            rep,
            "sandbox-exec",
            "unsupported",
            format!(
                "no_new_privs, Landlock and seccomp are Linux interfaces; \
                 unsupported on this platform ({})",
                std::env::consts::OS
            ),
        ));
    }
    if !syscalls.is_empty() && !cfg!(target_arch = "x86_64") {
        return Ok(refuse(
            rep,
            "seccomp",
            "unsupported",
            format!(
                "the fixture's syscall table is x86_64; unsupported on this architecture ({})",
                std::env::consts::ARCH
            ),
        ));
    }
    if session.failed_earlier() {
        let mut report = argv_report("execve", req.argv, ExecVia::Execve);
        report.set("refused", "earlier_expectation_failed");
        report.result(-1, None);
        let e = Emitted::unusable(report);
        rep.emit(&e.report);
        return Ok(false);
    }
    #[cfg(target_os = "linux")]
    if !linux::install(rep, req, &syscalls) {
        return Ok(false);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (req.rw, req.ro, req.deny_tcp);
    let report = argv_report("execve", req.argv, ExecVia::Execve);
    // On success this does not return and nothing more is reported.
    let emitted = finish(report, do_exec(&img, ExecVia::Execve));
    rep.emit(&emitted.report);
    Ok(emitted.satisfies(&Expect::Ok))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{OsString, c_int};
    use std::os::unix::ffi::OsStrExt;

    use serde_json::Value;

    use super::{
        ACCESS_NET_CONNECT_TCP, LANDLOCK_CREATE_RULESET_VERSION, LANDLOCK_RULE_PATH_BENEATH,
        PathBeneathAttr, RO_RIGHTS, Request, RulesetAttr, fs_rights, seccomp_program,
    };
    use crate::ops::finish;
    use crate::raw::{self, Attempt};
    use crate::report::{Emitted, Expect, OpReport, Reporter, path_value};

    fn step(rep: &Reporter, report: OpReport, attempt: Attempt) -> Option<i64> {
        let e = finish(report, attempt);
        rep.emit(&e.report);
        e.satisfies(&Expect::Ok).then_some(e.report.ret)
    }

    fn hex(v: u64) -> Value {
        Value::from(format!("{v:#x}"))
    }

    /// Run steps 1-3. `true` when every one of them succeeded.
    pub(super) fn install(rep: &Reporter, req: &Request<'_>, syscalls: &[(String, u32)]) -> bool {
        let mut r = OpReport::new("prctl");
        r.set("option", "PR_SET_NO_NEW_PRIVS");
        r.set("arg2", 1);
        r.set("mechanism", raw::mechanism());
        if step(rep, r, raw::prctl(libc::PR_SET_NO_NEW_PRIVS, 1)).is_none() {
            return false;
        }
        let fs_grants = !req.rw.is_empty() || !req.ro.is_empty();
        if (fs_grants || req.deny_tcp) && !landlock(rep, req) {
            return false;
        }
        syscalls.is_empty() || seccomp(rep, syscalls)
    }

    fn landlock(rep: &Reporter, req: &Request<'_>) -> bool {
        let mut r = OpReport::new("landlock_create_ruleset");
        r.set("flags", "LANDLOCK_CREATE_RULESET_VERSION");
        r.set("purpose", "abi_probe");
        r.set("mechanism", raw::mechanism());
        // SAFETY: a NULL attribute with size 0 is the documented form of the
        // version query.
        let probe = unsafe {
            raw::landlock_create_ruleset(std::ptr::null(), 0, LANDLOCK_CREATE_RULESET_VERSION)
        };
        let Some(abi) = step(rep, r, probe) else {
            return false;
        };

        let fs_grants = !req.rw.is_empty() || !req.ro.is_empty();
        let mut attr = RulesetAttr::default();
        if fs_grants {
            attr.handled_access_fs = fs_rights(abi);
        }
        if req.deny_tcp {
            if abi < 4 {
                let mut r = OpReport::new("landlock_create_ruleset");
                r.set("abi", abi);
                r.set(
                    "unsupported",
                    format!("TCP connect rules need Landlock ABI 4; this kernel has ABI {abi}"),
                );
                r.result(-1, None);
                rep.emit(&Emitted::unusable(r).report);
                return false;
            }
            attr.handled_access_net = ACCESS_NET_CONNECT_TCP;
        }
        let mut r = OpReport::new("landlock_create_ruleset");
        r.set("abi", abi);
        r.set("handled_access_fs", hex(attr.handled_access_fs));
        r.set("handled_access_net", hex(attr.handled_access_net));
        r.set("size", size_of::<RulesetAttr>());
        r.set("mechanism", raw::mechanism());
        // SAFETY: `attr` is a live `landlock_ruleset_attr` of exactly the
        // size passed; the kernel only reads it.
        let created = unsafe {
            raw::landlock_create_ruleset(
                std::ptr::from_ref(&attr).cast(),
                size_of::<RulesetAttr>(),
                0,
            )
        };
        let Some(ruleset) = step(rep, r, created) else {
            return false;
        };
        let ruleset = ruleset as c_int;

        let grants = req
            .rw
            .iter()
            .map(|d| (d, "rw", attr.handled_access_fs))
            .chain(
                req.ro
                    .iter()
                    .map(|d| (d, "ro", RO_RIGHTS & attr.handled_access_fs)),
            );
        for (dir, kind, access) in grants {
            if !add_rule(rep, ruleset, dir, kind, access) {
                crate::bounded::close(ruleset);
                return false;
            }
        }

        let mut r = OpReport::new("landlock_restrict_self");
        r.set("flags", 0);
        r.set("mechanism", raw::mechanism());
        let restricted = step(rep, r, raw::landlock_restrict_self(ruleset, 0));
        crate::bounded::close(ruleset);
        restricted.is_some()
    }

    fn add_rule(rep: &Reporter, ruleset: c_int, dir: &OsString, kind: &str, access: u64) -> bool {
        let mut r = OpReport::new("openat");
        path_value(&mut r.args, "path", dir);
        r.set("flags", "O_PATH|O_CLOEXEC");
        r.set("purpose", "landlock_path_beneath");
        r.set("mechanism", raw::mechanism());
        let c = match raw::cpath(dir) {
            Ok(c) => c,
            Err(e) => {
                r.set("refused", e.reason);
                r.result(-1, None);
                rep.emit(&Emitted::unusable(r).report);
                return false;
            }
        };
        let opened = raw::openat(
            libc::AT_FDCWD,
            c.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC,
            0,
        );
        let Some(fd) = step(rep, r, opened) else {
            return false;
        };
        let fd = fd as c_int;

        let attr = PathBeneathAttr {
            allowed_access: access,
            parent_fd: fd,
        };
        let mut r = OpReport::new("landlock_add_rule");
        r.set("rule_type", "LANDLOCK_RULE_PATH_BENEATH");
        path_value(
            &mut r.args,
            "path",
            std::ffi::OsStr::from_bytes(dir.as_bytes()),
        );
        r.set("grant", kind);
        r.set("allowed_access", hex(access));
        r.set("mechanism", raw::mechanism());
        // SAFETY: `attr` is a live, packed `landlock_path_beneath_attr`, the
        // layout `LANDLOCK_RULE_PATH_BENEATH` names; the kernel only reads it.
        let added = unsafe {
            raw::landlock_add_rule(
                ruleset,
                LANDLOCK_RULE_PATH_BENEATH,
                std::ptr::from_ref(&attr).cast(),
                0,
            )
        };
        let ok = step(rep, r, added).is_some();
        crate::bounded::close(fd);
        ok
    }

    fn seccomp(rep: &Reporter, syscalls: &[(String, u32)]) -> bool {
        let numbers: Vec<u32> = syscalls.iter().map(|(_, nr)| *nr).collect();
        let program: Vec<libc::sock_filter> = seccomp_program(&numbers)
            .into_iter()
            .map(|i| libc::sock_filter {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect();
        let fprog = libc::sock_fprog {
            len: program.len() as u16,
            filter: program.as_ptr().cast_mut(),
        };
        let mut r = OpReport::new("seccomp");
        r.set("operation", "SECCOMP_SET_MODE_FILTER");
        r.set("flags", 0);
        r.set(
            "syscalls",
            Value::Array(
                syscalls
                    .iter()
                    .map(|(n, _)| Value::from(n.as_str()))
                    .collect(),
            ),
        );
        r.set(
            "numbers",
            Value::Array(numbers.iter().map(|n| Value::from(*n)).collect()),
        );
        r.set("action", "SECCOMP_RET_ERRNO(EPERM)");
        r.set("arch", "x86_64");
        r.set("arch_mismatch_action", "SECCOMP_RET_KILL_PROCESS");
        r.set("x32_action", "SECCOMP_RET_KILL_PROCESS");
        r.set("instructions", program.len());
        r.set("mechanism", raw::mechanism());
        // SAFETY: `fprog` points at `program`, which holds exactly `len`
        // live instructions and outlives the call; the kernel copies them.
        let installed = unsafe { raw::seccomp_set_mode_filter(&raw const fprog, 0) };
        step(rep, r, installed).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filter_denies_exactly_the_named_numbers_on_x86_64() {
        let p = seccomp_program(&[83, 258]);
        assert_eq!(interpret(&p, AUDIT_ARCH_X86_64, 83), RET_ERRNO | 1);
        assert_eq!(interpret(&p, AUDIT_ARCH_X86_64, 258), RET_ERRNO | 1);
        for other in [0, 1, 59, 84, 257, 259, 1023] {
            assert_eq!(
                interpret(&p, AUDIT_ARCH_X86_64, other),
                RET_ALLOW,
                "{other}"
            );
        }
    }

    #[test]
    fn a_foreign_architecture_or_an_x32_number_never_reaches_the_table() {
        // The precondition the numbers rest on: they mean x86_64 syscalls
        // only. Try to get around it with i386 (0x40000003) and aarch64
        // (0xC00000B7), and with the x32 bit on a denied and an allowed nr.
        let p = seccomp_program(&[83]);
        for arch in [0x4000_0003, 0xC000_00B7, 0] {
            for nr in [83, 0, 59] {
                assert_eq!(interpret(&p, arch, nr), RET_KILL_PROCESS, "{arch:#x}/{nr}");
            }
        }
        assert_eq!(
            interpret(&p, AUDIT_ARCH_X86_64, X32_SYSCALL_BIT | 83),
            RET_KILL_PROCESS
        );
        assert_eq!(
            interpret(&p, AUDIT_ARCH_X86_64, X32_SYSCALL_BIT),
            RET_KILL_PROCESS
        );
    }

    #[test]
    fn the_largest_filter_keeps_every_jump_in_range() {
        let numbers: Vec<u32> = (0..MAX_SECCOMP_SYSCALLS as u32).collect();
        let p = seccomp_program(&numbers);
        assert!(p.len() <= 4096, "BPF_MAXINSNS");
        for (i, insn) in p.iter().enumerate() {
            if insn.code == JEQ_K || insn.code == JSET_K {
                assert!(i + 1 + usize::from(insn.jt.max(insn.jf)) < p.len());
            }
        }
        assert_eq!(interpret(&p, AUDIT_ARCH_X86_64, 255), RET_ERRNO | 1);
        assert_eq!(interpret(&p, AUDIT_ARCH_X86_64, 256), RET_ALLOW);
        assert_eq!(size_of::<Insn>(), 8, "struct sock_filter is 8 bytes");
    }

    #[test]
    fn syscall_names_resolve_dedupe_and_refuse() {
        let got = resolve_syscalls(&["mkdirat".into(), "83".into(), "mkdirat".into()]).unwrap();
        assert_eq!(
            got,
            vec![("mkdirat".to_string(), 258), ("83".to_string(), 83)]
        );
        assert!(
            resolve_syscalls(&["nosuchcall".into()])
                .unwrap_err()
                .contains("unknown syscall")
        );
        assert!(resolve_syscalls(&["1024".into()]).is_err());
        let too_many: Vec<String> = (0..=MAX_SECCOMP_SYSCALLS).map(|n| n.to_string()).collect();
        assert!(resolve_syscalls(&too_many).is_err());
        let mut names: Vec<&str> = X86_64_SYSCALLS.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "the table names each syscall once");
    }

    #[test]
    fn the_landlock_attributes_have_the_kernels_layout() {
        // The unsafe calls pass these by pointer: a padded path_beneath
        // attribute (16 bytes) would hand the kernel a wrong parent_fd.
        assert_eq!(size_of::<PathBeneathAttr>(), 12);
        assert_eq!(std::mem::offset_of!(PathBeneathAttr, parent_fd), 8);
        assert_eq!(size_of::<RulesetAttr>(), 24);
        assert_eq!(fs_rights(0), 0);
        assert_eq!(fs_rights(1).count_ones(), 13);
        assert_eq!(fs_rights(2).count_ones(), 14);
        assert_eq!(fs_rights(4).count_ones(), 15);
        assert_eq!(fs_rights(5).count_ones(), 16);
        assert_eq!(
            fs_rights(8),
            fs_rights(5),
            "nothing is claimed beyond ABI 5's rights"
        );
        assert_eq!(RO_RIGHTS & fs_rights(1), RO_RIGHTS);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn the_table_matches_the_kernels_numbers() {
        macro_rules! check {
            ($($name:ident),* $(,)?) => {{
                let mut checked = 0usize;
                $(
                    let nr = X86_64_SYSCALLS
                        .iter()
                        .find(|(n, _)| *n == stringify!($name))
                        .map(|(_, nr)| i64::from(*nr));
                    assert_eq!(nr, Some(paste_sys!($name)), stringify!($name));
                    checked += 1;
                )*
                checked
            }};
        }
        macro_rules! paste_sys {
            ($name:ident) => {
                i64::from(sys::$name)
            };
        }
        mod sys {
            pub use libc::{
                SYS_accept as accept, SYS_accept4 as accept4, SYS_add_key as add_key,
                SYS_bind as bind, SYS_bpf as bpf, SYS_chdir as chdir, SYS_chmod as chmod,
                SYS_chown as chown, SYS_chroot as chroot, SYS_clone as clone, SYS_clone3 as clone3,
                SYS_close as close, SYS_connect as connect, SYS_creat as creat, SYS_dup as dup,
                SYS_dup2 as dup2, SYS_dup3 as dup3, SYS_execve as execve, SYS_execveat as execveat,
                SYS_faccessat as faccessat, SYS_faccessat2 as faccessat2, SYS_fchdir as fchdir,
                SYS_fchmod as fchmod, SYS_fchmodat as fchmodat, SYS_fchown as fchown,
                SYS_fchownat as fchownat, SYS_fcntl as fcntl, SYS_flock as flock, SYS_fork as fork,
                SYS_fsconfig as fsconfig, SYS_fsmount as fsmount, SYS_fsopen as fsopen,
                SYS_fspick as fspick, SYS_fstat as fstat, SYS_ftruncate as ftruncate,
                SYS_getcwd as getcwd, SYS_getpid as getpid, SYS_gettid as gettid,
                SYS_io_uring_enter as io_uring_enter, SYS_io_uring_register as io_uring_register,
                SYS_io_uring_setup as io_uring_setup, SYS_ioctl as ioctl, SYS_keyctl as keyctl,
                SYS_kill as kill, SYS_landlock_add_rule as landlock_add_rule,
                SYS_landlock_create_ruleset as landlock_create_ruleset,
                SYS_landlock_restrict_self as landlock_restrict_self, SYS_lchown as lchown,
                SYS_link as link, SYS_linkat as linkat, SYS_listen as listen, SYS_lstat as lstat,
                SYS_memfd_create as memfd_create, SYS_mkdir as mkdir, SYS_mkdirat as mkdirat,
                SYS_mknod as mknod, SYS_mknodat as mknodat, SYS_mmap as mmap, SYS_mount as mount,
                SYS_mount_setattr as mount_setattr, SYS_move_mount as move_mount,
                SYS_mprotect as mprotect, SYS_name_to_handle_at as name_to_handle_at,
                SYS_newfstatat as newfstatat, SYS_open as open,
                SYS_open_by_handle_at as open_by_handle_at, SYS_open_tree as open_tree,
                SYS_openat as openat, SYS_openat2 as openat2,
                SYS_perf_event_open as perf_event_open, SYS_personality as personality,
                SYS_pidfd_getfd as pidfd_getfd, SYS_pidfd_open as pidfd_open,
                SYS_pidfd_send_signal as pidfd_send_signal, SYS_pipe as pipe, SYS_pipe2 as pipe2,
                SYS_pivot_root as pivot_root, SYS_poll as poll, SYS_prctl as prctl,
                SYS_process_vm_readv as process_vm_readv,
                SYS_process_vm_writev as process_vm_writev, SYS_ptrace as ptrace, SYS_read as read,
                SYS_readlink as readlink, SYS_readlinkat as readlinkat, SYS_recvfrom as recvfrom,
                SYS_recvmsg as recvmsg, SYS_rename as rename, SYS_renameat as renameat,
                SYS_renameat2 as renameat2, SYS_request_key as request_key, SYS_rmdir as rmdir,
                SYS_seccomp as seccomp, SYS_sendmsg as sendmsg, SYS_sendto as sendto,
                SYS_setdomainname as setdomainname, SYS_setgid as setgid,
                SYS_sethostname as sethostname, SYS_setns as setns, SYS_setsid as setsid,
                SYS_setsockopt as setsockopt, SYS_setuid as setuid, SYS_shutdown as shutdown,
                SYS_socket as socket, SYS_socketpair as socketpair, SYS_stat as stat,
                SYS_statx as statx, SYS_symlink as symlink, SYS_symlinkat as symlinkat,
                SYS_tkill as tkill, SYS_truncate as truncate, SYS_umount2 as umount2,
                SYS_uname as uname, SYS_unlink as unlink, SYS_unlinkat as unlinkat,
                SYS_unshare as unshare, SYS_userfaultfd as userfaultfd, SYS_vfork as vfork,
                SYS_write as write,
            };
        }
        let checked = check![
            read,
            write,
            open,
            close,
            stat,
            fstat,
            lstat,
            poll,
            mmap,
            mprotect,
            ioctl,
            pipe,
            dup,
            dup2,
            getpid,
            socket,
            connect,
            accept,
            sendto,
            recvfrom,
            sendmsg,
            recvmsg,
            shutdown,
            bind,
            listen,
            socketpair,
            setsockopt,
            clone,
            fork,
            vfork,
            execve,
            kill,
            uname,
            fcntl,
            flock,
            truncate,
            ftruncate,
            getcwd,
            chdir,
            fchdir,
            rename,
            mkdir,
            rmdir,
            creat,
            link,
            unlink,
            symlink,
            readlink,
            chmod,
            fchmod,
            chown,
            fchown,
            lchown,
            ptrace,
            setuid,
            setgid,
            setsid,
            mknod,
            personality,
            pivot_root,
            prctl,
            chroot,
            mount,
            umount2,
            sethostname,
            setdomainname,
            gettid,
            tkill,
            add_key,
            request_key,
            keyctl,
            openat,
            mkdirat,
            mknodat,
            fchownat,
            newfstatat,
            unlinkat,
            renameat,
            linkat,
            symlinkat,
            readlinkat,
            fchmodat,
            faccessat,
            unshare,
            accept4,
            dup3,
            pipe2,
            perf_event_open,
            name_to_handle_at,
            open_by_handle_at,
            setns,
            process_vm_readv,
            process_vm_writev,
            renameat2,
            seccomp,
            memfd_create,
            bpf,
            execveat,
            userfaultfd,
            statx,
            pidfd_send_signal,
            io_uring_setup,
            io_uring_enter,
            io_uring_register,
            open_tree,
            move_mount,
            fsopen,
            fsconfig,
            fsmount,
            fspick,
            pidfd_open,
            clone3,
            openat2,
            pidfd_getfd,
            faccessat2,
            mount_setattr,
            landlock_create_ruleset,
            landlock_add_rule,
            landlock_restrict_self,
        ];
        assert_eq!(
            checked,
            X86_64_SYSCALLS.len(),
            "every table entry is checked"
        );
    }
}
