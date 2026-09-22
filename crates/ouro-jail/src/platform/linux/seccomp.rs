//! The `tool` seccomp baseline, built from [`super::bpf`].
//!
//! Spec: jail-v1 §9.2, north-star §4.3. The filter is architecture-aware, it
//! is recorded by digest, and every rule here has a live test on the
//! reference host that makes the raw syscall inside the jail and reports its
//! errno. A rule with no such test would be a claim, not a boundary.
//!
//! Syscall numbers are the x86_64 ABI. They are written out rather than taken
//! from `libc` so that the table is the same whatever host builds it, and a
//! Linux-only test checks every one of them against the kernel headers
//! installed on the build host.

use super::bpf::{Asm, BpfError, Program};

/// `AUDIT_ARCH_X86_64` from `linux/audit.h`.
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// Bit set in the syscall number for the x32 ABI (`__X32_SYSCALL_BIT`).
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// `SECCOMP_RET_ALLOW`.
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// `SECCOMP_RET_ERRNO`, to be combined with an errno in the low 16 bits.
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
/// `SECCOMP_RET_TRACE`, used by the observer's narrowing filter.
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;

/// Linux `EPERM`. Spelled out because the filter targets the Linux ABI
/// regardless of the host that builds it.
pub const LINUX_EPERM: u32 = 1;
/// Linux `ENOSYS`.
pub const LINUX_ENOSYS: u32 = 38;

/// Verdict for a denied syscall.
#[must_use]
pub const fn ret_errno(errno: u32) -> u32 {
    SECCOMP_RET_ERRNO | (errno & 0x0000_ffff)
}

// Offsets into `struct seccomp_data`.
/// Offset of `nr`.
pub const SD_NR: u32 = 0;
/// Offset of `arch`.
pub const SD_ARCH: u32 = 4;

/// Offset of the low 32 bits of `args[index]` on a little-endian host.
#[must_use]
pub const fn sd_arg_low(index: u32) -> u32 {
    16 + 8 * index
}

// ---------------------------------------------------------------------------
// The syscall table
// ---------------------------------------------------------------------------

/// Syscalls denied outright with `EPERM`, as x86_64 numbers.
///
/// The list is jail-v1 §9.2 verbatim: host tracing and inspection, kernel
/// replacement and modules, the keyring, all three `io_uring` entry points,
/// every mount interface old and new, and namespace entry.
pub const DENY_EPERM: &[(&str, u32)] = &[
    ("ptrace", 101),
    ("process_vm_readv", 310),
    ("process_vm_writev", 311),
    ("bpf", 321),
    ("perf_event_open", 298),
    ("kexec_load", 246),
    ("kexec_file_load", 320),
    ("init_module", 175),
    ("finit_module", 313),
    ("delete_module", 176),
    ("keyctl", 250),
    ("add_key", 248),
    ("request_key", 249),
    ("io_uring_setup", 425),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
    ("mount", 165),
    ("umount2", 166),
    ("move_mount", 429),
    ("open_tree", 428),
    ("fsopen", 430),
    ("fsmount", 432),
    ("fspick", 433),
    ("fsconfig", 431),
    ("mount_setattr", 442),
    ("pivot_root", 155),
    ("chroot", 161),
    ("unshare", 272),
    ("setns", 308),
];

/// `clone3`. Denied with `ENOSYS` because seccomp cannot safely dereference
/// its argument structure; glibc falls back to `clone`, which this filter can
/// inspect (jail-v1 §9.2).
pub const NR_CLONE3: u32 = 435;
/// `clone`.
pub const NR_CLONE: u32 = 56;
/// `socket`.
pub const NR_SOCKET: u32 = 41;
/// `socketpair`.
pub const NR_SOCKETPAIR: u32 = 53;
/// `ioctl`.
pub const NR_IOCTL: u32 = 16;

/// `AF_UNIX`, compared against argument 0 of `socket` and `socketpair`.
pub const AF_UNIX: u32 = 1;
/// `TIOCSTI`, compared against argument 1 of `ioctl`.
pub const TIOCSTI: u32 = 0x5412;

/// Namespace bits in `clone`'s flags, checked as a mask against argument 0.
pub const CLONE_NS_MASK: u32 = CLONE_NEWTIME
    | CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET;

const CLONE_NEWTIME: u32 = 0x0000_0080;
const CLONE_NEWNS: u32 = 0x0002_0000;
const CLONE_NEWCGROUP: u32 = 0x0200_0000;
const CLONE_NEWUTS: u32 = 0x0400_0000;
const CLONE_NEWIPC: u32 = 0x0800_0000;
const CLONE_NEWUSER: u32 = 0x1000_0000;
const CLONE_NEWPID: u32 = 0x2000_0000;
const CLONE_NEWNET: u32 = 0x4000_0000;

// ---------------------------------------------------------------------------
// The program
// ---------------------------------------------------------------------------

const L_ALLOW: &str = "allow";
const L_DENY_EPERM: &str = "deny_eperm";
const L_DENY_ENOSYS: &str = "deny_enosys";
const L_CLONE_FLAGS: &str = "clone_flags";
const L_AF_UNIX: &str = "af_unix";
const L_IOCTL: &str = "ioctl_arg";

/// Build the `tool` baseline filter.
///
/// The architecture is checked before any syscall number is compared, so a
/// number that means one thing on x86_64 and another elsewhere can never be
/// matched against the wrong table (jail-v1 §9.2).
///
/// # Errors
///
/// Returns [`BpfError`] only if the table grows past what classic BPF can
/// encode; with the current table it cannot fail, and a test asserts that.
pub fn tool_baseline() -> Result<Program, BpfError> {
    let mut asm = Asm::new();

    // Architecture first. Anything that is not x86_64 is denied outright.
    asm.ld_w_abs(SD_ARCH)
        .jeq(AUDIT_ARCH_X86_64, None, Some(L_DENY_EPERM));

    // Then the syscall number. x32 shares the x86_64 audit arch but uses a
    // distinct numbering; deny it rather than mismatch the table.
    asm.ld_w_abs(SD_NR)
        .jset(X32_SYSCALL_BIT, Some(L_DENY_EPERM), None);

    for (_, nr) in DENY_EPERM {
        asm.jeq(*nr, Some(L_DENY_EPERM), None);
    }
    asm.jeq(NR_CLONE3, Some(L_DENY_ENOSYS), None);
    asm.jeq(NR_CLONE, Some(L_CLONE_FLAGS), None);
    asm.jeq(NR_SOCKET, Some(L_AF_UNIX), None);
    asm.jeq(NR_SOCKETPAIR, Some(L_AF_UNIX), None);
    asm.jeq(NR_IOCTL, Some(L_IOCTL), None);
    asm.ja(L_ALLOW);

    // clone: deny when any namespace bit is set. Every namespace flag lives
    // in the low 32 bits, so the low word is the whole question.
    asm.label(L_CLONE_FLAGS)
        .ld_w_abs(sd_arg_low(0))
        .jset(CLONE_NS_MASK, Some(L_DENY_EPERM), None)
        .ja(L_ALLOW);

    // socket/socketpair: deny AF_UNIX. Other families stay allowed; the
    // network namespace, not this rule, is what denies egress.
    asm.label(L_AF_UNIX)
        .ld_w_abs(sd_arg_low(0))
        .jeq(AF_UNIX, Some(L_DENY_EPERM), None)
        .ja(L_ALLOW);

    // ioctl: deny terminal injection.
    asm.label(L_IOCTL)
        .ld_w_abs(sd_arg_low(1))
        .jeq(TIOCSTI, Some(L_DENY_EPERM), None)
        .ja(L_ALLOW);

    asm.label(L_ALLOW).ret(SECCOMP_RET_ALLOW);
    asm.label(L_DENY_EPERM).ret(ret_errno(LINUX_EPERM));
    asm.label(L_DENY_ENOSYS).ret(ret_errno(LINUX_ENOSYS));

    asm.assemble()
}

/// A human-readable table of what the baseline does, for the evidence file
/// the conformance run keeps. It is generated from the same constants the
/// filter is generated from, so the two cannot drift.
#[must_use]
pub fn tool_baseline_table() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    out.push_str("ouro-jail `tool` seccomp baseline (x86_64)\n");
    out.push_str("jail-v1 §9.2, north-star §4.3\n\n");
    out.push_str("precondition              action\n");
    let _ = writeln!(
        out,
        "arch != AUDIT_ARCH_X86_64  EPERM   (0x{AUDIT_ARCH_X86_64:08x} required)"
    );
    let _ = writeln!(
        out,
        "nr & 0x{X32_SYSCALL_BIT:08x}           EPERM   (x32 ABI)"
    );
    out.push_str("\nsyscall                nr     action\n");
    for (name, nr) in DENY_EPERM {
        let _ = writeln!(out, "{name:<22} {nr:<6} EPERM");
    }
    let _ = writeln!(
        out,
        "{:<22} {:<6} ENOSYS  (argument struct not inspectable)",
        "clone3", NR_CLONE3
    );
    let _ = writeln!(
        out,
        "{:<22} {:<6} EPERM when args[0] & 0x{CLONE_NS_MASK:08x} != 0",
        "clone", NR_CLONE
    );
    let _ = writeln!(
        out,
        "{:<22} {:<6} EPERM when args[0] == {AF_UNIX} (AF_UNIX)",
        "socket", NR_SOCKET
    );
    let _ = writeln!(
        out,
        "{:<22} {:<6} EPERM when args[0] == {AF_UNIX} (AF_UNIX)",
        "socketpair", NR_SOCKETPAIR
    );
    let _ = writeln!(
        out,
        "{:<22} {:<6} EPERM when args[1] == 0x{TIOCSTI:04x} (TIOCSTI)",
        "ioctl", NR_IOCTL
    );
    out.push_str("\neverything else        ALLOW\n");
    if let Ok(prog) = tool_baseline() {
        let _ = writeln!(out, "\ninstructions: {}", prog.len());
        let _ = writeln!(out, "digest: {}", prog.digest());
        out.push_str("\ndisassembly\n");
        for line in prog.disassemble() {
            let _ = writeln!(out, "{line}");
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Handing the program to bubblewrap and to the kernel
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_only {
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};

    use super::Program;

    /// Write `program`'s raw bytes into a pipe and return its read end, which
    /// is what `bwrap --seccomp FD` consumes.
    ///
    /// The write end is closed before returning, so bubblewrap sees EOF. The
    /// program is a few hundred bytes, far below the pipe buffer, so the
    /// write cannot block.
    ///
    /// # Errors
    ///
    /// Any failure of `pipe2` or `write`.
    pub fn program_pipe(program: &Program) -> io::Result<OwnedFd> {
        let bytes = program.to_bytes();
        assert!(
            bytes.len() < 32 * 1024,
            "filter must fit in a pipe buffer without a writer thread"
        );
        let mut fds = [-1i32; 2];
        // SAFETY: `fds` is a two-element array of the right type; pipe2 writes
        // exactly two descriptors into it or returns -1.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors were just created by pipe2 and are owned
        // here; wrapping them transfers that ownership.
        let (read_end, write_end) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

        let mut written = 0usize;
        while written < bytes.len() {
            // SAFETY: the pointer and length address `bytes[written..]`, which
            // is live for the duration of the call.
            let n = unsafe {
                libc::write(
                    std::os::fd::AsRawFd::as_raw_fd(&write_end),
                    bytes.as_ptr().add(written).cast::<libc::c_void>(),
                    bytes.len() - written,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            written += usize::try_from(n).expect("write returns a non-negative count here");
        }
        drop(write_end);
        Ok(read_end)
    }

    /// Install `program` on the calling thread with `SECCOMP_SET_MODE_FILTER`.
    ///
    /// The caller must already have set `no_new_privs`, or the kernel refuses
    /// with `EACCES`.
    ///
    /// # Errors
    ///
    /// The raw errno from the `seccomp` syscall.
    pub fn install(program: &Program) -> io::Result<()> {
        let fprog = program.sock_fprog();
        // SAFETY: `fprog` points at `program`'s instruction slice, which
        // outlives this call; SECCOMP_SET_MODE_FILTER reads it and copies it
        // into the kernel before returning.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                std::ptr::from_ref(&fprog),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Set `PR_SET_NO_NEW_PRIVS`.
    ///
    /// # Errors
    ///
    /// The raw errno from `prctl`.
    pub fn set_no_new_privs() -> io::Result<()> {
        // SAFETY: PR_SET_NO_NEW_PRIVS takes a single scalar argument and
        // dereferences nothing.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux_only::{install, program_pipe, set_no_new_privs};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_baseline_assembles() {
        let prog = tool_baseline().expect("the table fits classic BPF");
        assert!(prog.len() > DENY_EPERM.len());
        assert!(prog.len() < 4096);
    }

    #[test]
    fn architecture_is_checked_before_any_syscall_number() {
        let prog = tool_baseline().unwrap();
        let insns = prog.insns();
        assert_eq!(insns[0].code, super::super::bpf::CODE_LD_W_ABS);
        assert_eq!(insns[0].k, SD_ARCH, "the first load is the architecture");
        assert_eq!(insns[1].code, super::super::bpf::CODE_JEQ_K);
        assert_eq!(insns[1].k, AUDIT_ARCH_X86_64);
        assert_eq!(insns[2].k, SD_NR, "the syscall number is loaded second");
    }

    #[test]
    fn the_three_verdicts_are_the_last_three_instructions() {
        let prog = tool_baseline().unwrap();
        let insns = prog.insns();
        let n = insns.len();
        assert_eq!(insns[n - 3].k, SECCOMP_RET_ALLOW);
        assert_eq!(insns[n - 2].k, ret_errno(LINUX_EPERM));
        assert_eq!(insns[n - 1].k, ret_errno(LINUX_ENOSYS));
    }

    #[test]
    fn the_namespace_mask_is_the_eight_namespace_flags() {
        assert_eq!(CLONE_NS_MASK, 0x7e02_0080);
        // The flags glibc uses to create a thread must not be caught by it.
        const CLONE_VM: u32 = 0x0000_0100;
        const CLONE_FS: u32 = 0x0000_0200;
        const CLONE_FILES: u32 = 0x0000_0400;
        const CLONE_SIGHAND: u32 = 0x0000_0800;
        const CLONE_THREAD: u32 = 0x0001_0000;
        const CLONE_SYSVSEM: u32 = 0x0004_0000;
        const CLONE_SETTLS: u32 = 0x0008_0000;
        const CLONE_PARENT_SETTID: u32 = 0x0010_0000;
        const CLONE_CHILD_CLEARTID: u32 = 0x0020_0000;
        let thread_flags = CLONE_VM
            | CLONE_FS
            | CLONE_FILES
            | CLONE_SIGHAND
            | CLONE_THREAD
            | CLONE_SYSVSEM
            | CLONE_SETTLS
            | CLONE_PARENT_SETTID
            | CLONE_CHILD_CLEARTID;
        assert_eq!(thread_flags & CLONE_NS_MASK, 0);
    }

    #[test]
    fn seccomp_data_offsets_follow_the_struct() {
        assert_eq!(SD_NR, 0);
        assert_eq!(SD_ARCH, 4);
        assert_eq!(sd_arg_low(0), 16);
        assert_eq!(sd_arg_low(1), 24);
        assert_eq!(sd_arg_low(5), 56);
    }

    #[test]
    fn the_table_lists_every_rule_the_filter_encodes() {
        let table = tool_baseline_table();
        for (name, _) in DENY_EPERM {
            assert!(table.contains(name), "table omits {name}");
        }
        for name in ["clone3", "clone", "socket", "socketpair", "ioctl"] {
            assert!(table.contains(name), "table omits {name}");
        }
        assert!(table.contains(&tool_baseline().unwrap().digest()));
    }

    #[test]
    fn no_syscall_number_appears_twice() {
        let mut seen = std::collections::HashSet::new();
        for (name, nr) in DENY_EPERM {
            assert!(seen.insert(*nr), "{name} ({nr}) listed twice");
        }
        for nr in [NR_CLONE3, NR_CLONE, NR_SOCKET, NR_SOCKETPAIR, NR_IOCTL] {
            assert!(seen.insert(nr), "{nr} listed twice");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_spelled_out_errnos_match_this_kernel() {
        assert_eq!(LINUX_EPERM, u32::try_from(libc::EPERM).unwrap());
        assert_eq!(LINUX_ENOSYS, u32::try_from(libc::ENOSYS).unwrap());
    }
}
