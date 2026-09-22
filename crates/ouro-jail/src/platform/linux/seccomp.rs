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
    // Defense in depth beyond the spec's named list: page-fault control
    // widens kernel race windows, handle-based opens can walk outside the
    // bind view given a reachable mount fd, and the kernel log discloses
    // host memory addresses where dmesg_restrict is lax.
    ("userfaultfd", 323),
    ("open_by_handle_at", 304),
    ("name_to_handle_at", 303),
    ("syslog", 103),
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

/// What distinguishes one contained baseline from another. Every baseline
/// shares the architecture check, the x32 denial, `clone3` as `ENOSYS` and
/// the terminal-injection rule; the shape says which of the rest apply.
struct Shape {
    /// Syscalls denied outright with `EPERM`.
    deny: Vec<(&'static str, u32)>,
    /// Deny `clone` with any namespace flag.
    clone_namespaces_denied: bool,
    /// Deny every AF_UNIX `socket`/`socketpair`. `agent` leaves AF_UNIX to
    /// the mediation filter ([`mediation_filter`]), which admits only stream
    /// and seqpacket sockets.
    af_unix_denied: bool,
}

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
    build(&Shape {
        deny: DENY_EPERM.to_vec(),
        clone_namespaces_denied: true,
        af_unix_denied: true,
    })
}

fn build(shape: &Shape) -> Result<Program, BpfError> {
    let mut asm = Asm::new();

    // Architecture first. Anything that is not x86_64 is denied outright.
    asm.ld_w_abs(SD_ARCH)
        .jeq(AUDIT_ARCH_X86_64, None, Some(L_DENY_EPERM));

    // Then the syscall number. x32 shares the x86_64 audit arch but uses a
    // distinct numbering; deny it rather than mismatch the table.
    asm.ld_w_abs(SD_NR)
        .jset(X32_SYSCALL_BIT, Some(L_DENY_EPERM), None);

    for (_, nr) in &shape.deny {
        asm.jeq(*nr, Some(L_DENY_EPERM), None);
    }
    asm.jeq(NR_CLONE3, Some(L_DENY_ENOSYS), None);
    if shape.clone_namespaces_denied {
        asm.jeq(NR_CLONE, Some(L_CLONE_FLAGS), None);
    }
    if shape.af_unix_denied {
        asm.jeq(NR_SOCKET, Some(L_AF_UNIX), None);
        asm.jeq(NR_SOCKETPAIR, Some(L_AF_UNIX), None);
    }
    asm.jeq(NR_IOCTL, Some(L_IOCTL), None);
    asm.ja(L_ALLOW);

    if shape.clone_namespaces_denied {
        // clone: deny when any namespace bit is set. Every namespace flag
        // lives in the low 32 bits, so the low word is the whole question.
        asm.label(L_CLONE_FLAGS)
            .ld_w_abs(sd_arg_low(0))
            .jset(CLONE_NS_MASK, Some(L_DENY_EPERM), None)
            .ja(L_ALLOW);
    }

    if shape.af_unix_denied {
        // socket/socketpair: deny AF_UNIX. Other families stay allowed; the
        // network namespace, not this rule, is what denies egress.
        asm.label(L_AF_UNIX)
            .ld_w_abs(sd_arg_low(0))
            .jeq(AF_UNIX, Some(L_DENY_EPERM), None)
            .ja(L_ALLOW);
    }

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

// ---------------------------------------------------------------------------
// The `agent` filters (jail-v1 §9.2, §10)
// ---------------------------------------------------------------------------

/// Which `agent` baseline a run installs, chosen by the measured
/// `nested_user_namespace` capability (jail-v1 §9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentVariant {
    /// The host denies a user namespace inside the outer one (a stock
    /// Ubuntu host). The inner sandboxes that work anyway are the
    /// unprivileged ones — `no_new_privs`, seccomp, Landlock — which the
    /// baseline leaves allowed; namespace creation, every mount interface and
    /// `clone3` stay exactly as `tool` has them, so an inner namespace
    /// sandbox fails visibly with `EPERM`.
    UnprivilegedInner,
    /// The host permits nested user namespaces. The baseline additionally
    /// permits the setup a namespace inner sandbox performs
    /// ([`NAMESPACE_SETUP`] and namespace flags in `clone`). Every one of
    /// them needs a capability the outer user namespace does not grant, so
    /// it succeeds only inside a namespace the child creates, whose mounts
    /// inherited from the outer view stay locked. Unit-tested only: the
    /// reference host is stock and never selects it.
    NamespaceInner,
}

impl AgentVariant {
    /// The receipt spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AgentVariant::UnprivilegedInner => "unprivileged_inner",
            AgentVariant::NamespaceInner => "namespace_inner",
        }
    }

    /// The variant a measured nested-user-namespace capability selects.
    #[must_use]
    pub fn for_nested_user_namespace(available: bool) -> Self {
        if available {
            AgentVariant::NamespaceInner
        } else {
            AgentVariant::UnprivilegedInner
        }
    }

    /// The inner-sandbox setup operations this variant permits, for the
    /// receipt (jail-v1 §9.2: "Record the allowed setup operations").
    #[must_use]
    pub fn allowed_setup_operations(self) -> Vec<&'static str> {
        let mut out = UNPRIVILEGED_SETUP.to_vec();
        if self == AgentVariant::NamespaceInner {
            out.extend(NAMESPACE_SETUP.iter().map(|(name, _)| *name));
            out.push("clone_namespace_flags");
        }
        out
    }
}

/// The unprivileged sandboxing every `agent` baseline leaves allowed, by
/// name. None of them is in any deny list; they are named so the receipt
/// and the table say what the inner sandbox may do.
pub const UNPRIVILEGED_SETUP: [&str; 5] = [
    "prctl(PR_SET_NO_NEW_PRIVS)",
    "seccomp",
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
];

/// The namespace setup the `NamespaceInner` baseline removes from the
/// deny list. `setns`, the new mount API, `clone3` and every host-inspection
/// rule stay denied in both variants.
pub const NAMESPACE_SETUP: [(&str, u32); 5] = [
    ("mount", 165),
    ("umount2", 166),
    ("pivot_root", 155),
    ("chroot", 161),
    ("unshare", 272),
];

/// The `agent` baseline bubblewrap loads, in `variant`.
///
/// It is the `tool` baseline without the AF_UNIX denial (the mediation
/// filter restricts AF_UNIX to stream and seqpacket and mediates every
/// `connect`) and, in [`AgentVariant::NamespaceInner`] only, without the
/// namespace-setup denials. Architecture and x32 checks, the host
/// inspection, kernel, keyring and io_uring denials, `clone3` as `ENOSYS`
/// and the terminal-injection rule are identical to `tool`.
///
/// # Errors
///
/// [`BpfError`] only if the table outgrows classic BPF; a test asserts it
/// cannot with the current tables.
pub fn agent_baseline(variant: AgentVariant) -> Result<Program, BpfError> {
    let deny = match variant {
        AgentVariant::UnprivilegedInner => DENY_EPERM.to_vec(),
        AgentVariant::NamespaceInner => DENY_EPERM
            .iter()
            .filter(|(name, _)| !NAMESPACE_SETUP.iter().any(|(setup, _)| setup == name))
            .copied()
            .collect(),
    };
    build(&Shape {
        deny,
        clone_namespaces_denied: variant == AgentVariant::UnprivilegedInner,
        af_unix_denied: false,
    })
}

/// `connect` on x86_64.
pub const NR_CONNECT: u32 = 42;
/// `SOCK_TYPE_MASK`: the bits of a socket type below the creation flags.
pub const SOCK_TYPE_MASK: u32 = 0xf;
/// `SOCK_STREAM`.
pub const SOCK_STREAM: u32 = 1;
/// `SOCK_SEQPACKET`.
pub const SOCK_SEQPACKET: u32 = 5;
/// `SECCOMP_RET_USER_NOTIF`.
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

/// The `agent` mediation filter: `connect` notifies the supervisor's
/// listener, and AF_UNIX sockets are stream or seqpacket only (jail-v1 §10).
/// Installed by the trusted launcher with its own notification listener;
/// see `unixpeer::mediation_program` for the decision it hands the
/// supervisor.
///
/// # Errors
///
/// [`BpfError`] only if the assembler rejects the program, which a test
/// asserts it does not.
pub fn mediation_filter() -> Result<Program, BpfError> {
    const ALLOW: &str = "allow";
    const NOTIFY: &str = "notify";
    const DENY: &str = "deny";
    const SOCKET: &str = "socket_family";
    let mut asm = Asm::new();
    asm.ld_w_abs(SD_ARCH)
        .jeq(AUDIT_ARCH_X86_64, None, Some(DENY));
    asm.ld_w_abs(SD_NR)
        .jset(X32_SYSCALL_BIT, Some(DENY), None)
        .jeq(NR_CONNECT, Some(NOTIFY), None)
        .jeq(NR_SOCKET, Some(SOCKET), None)
        .jeq(NR_SOCKETPAIR, Some(SOCKET), None)
        .ja(ALLOW);
    // socket/socketpair: a non-AF_UNIX family is the network namespace's
    // question, not this filter's; AF_UNIX must be stream or seqpacket, with
    // SOCK_CLOEXEC/SOCK_NONBLOCK masked off before the comparison.
    asm.label(SOCKET)
        .ld_w_abs(sd_arg_low(0))
        .jeq(AF_UNIX, None, Some(ALLOW))
        .ld_w_abs(sd_arg_low(1))
        .and_k(SOCK_TYPE_MASK)
        .jeq(SOCK_STREAM, Some(ALLOW), None)
        .jeq(SOCK_SEQPACKET, Some(ALLOW), None)
        .ja(DENY);
    asm.label(ALLOW).ret(SECCOMP_RET_ALLOW);
    asm.label(NOTIFY).ret(SECCOMP_RET_USER_NOTIF);
    asm.label(DENY).ret(ret_errno(LINUX_EPERM));
    asm.assemble()
}

/// The `agent` baseline's table, generated from the same constants as the
/// filter, like [`tool_baseline_table`].
#[must_use]
pub fn agent_baseline_table(variant: AgentVariant) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "ouro-jail `agent` seccomp baseline (x86_64), variant {}",
        variant.as_str()
    );
    out.push_str(
        "jail-v1 §9.2 and §10; stacked with the mediation filter below

",
    );
    let _ = writeln!(
        out,
        "arch != AUDIT_ARCH_X86_64  EPERM   (0x{AUDIT_ARCH_X86_64:08x} required)"
    );
    let _ = writeln!(
        out,
        "nr & 0x{X32_SYSCALL_BIT:08x}           EPERM   (x32 ABI)"
    );
    out.push_str(
        "
syscall                nr     action
",
    );
    let permitted: &[(&str, u32)] = match variant {
        AgentVariant::UnprivilegedInner => &[],
        AgentVariant::NamespaceInner => &NAMESPACE_SETUP,
    };
    for (name, nr) in DENY_EPERM {
        if permitted.iter().any(|(setup, _)| setup == name) {
            let _ = writeln!(out, "{name:<22} {nr:<6} ALLOW   (namespace inner sandbox)");
        } else {
            let _ = writeln!(out, "{name:<22} {nr:<6} EPERM");
        }
    }
    let _ = writeln!(
        out,
        "{:<22} {:<6} ENOSYS  (argument struct not inspectable)",
        "clone3", NR_CLONE3
    );
    if variant == AgentVariant::UnprivilegedInner {
        let _ = writeln!(
            out,
            "{:<22} {:<6} EPERM when args[0] & 0x{CLONE_NS_MASK:08x} != 0",
            "clone", NR_CLONE
        );
    } else {
        let _ = writeln!(
            out,
            "{:<22} {:<6} ALLOW   (namespace flags permitted)",
            "clone", NR_CLONE
        );
    }
    let _ = writeln!(
        out,
        "{:<22} {:<6} EPERM when args[1] == 0x{TIOCSTI:04x} (TIOCSTI)",
        "ioctl", NR_IOCTL
    );
    for name in UNPRIVILEGED_SETUP {
        let _ = writeln!(out, "{name:<30} ALLOW   (unprivileged inner sandbox)");
    }
    out.push_str(
        "socket, socketpair             ALLOW   (AF_UNIX restricted by the mediation filter)
",
    );
    out.push_str(
        "
everything else        ALLOW
",
    );
    if let Ok(prog) = agent_baseline(variant) {
        let _ = writeln!(
            out,
            "
instructions: {}",
            prog.len()
        );
        let _ = writeln!(out, "digest: {}", prog.digest());
    }
    out.push_str(
        "
mediation filter (installed by the launcher with its own listener)
",
    );
    let _ = writeln!(out, "connect                {NR_CONNECT:<6} USER_NOTIF");
    let _ = writeln!(
        out,
        "socket, socketpair     AF_UNIX: ALLOW only (type & 0x{SOCK_TYPE_MASK:x}) in {{STREAM, SEQPACKET}}, else EPERM"
    );
    if let Ok(prog) = mediation_filter() {
        let _ = writeln!(out, "instructions: {}", prog.len());
        let _ = writeln!(out, "digest: {}", prog.digest());
    }
    out
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

    // -- J3 agent: the agent baseline and the mediation filter ------------

    /// A classic-BPF interpreter over the fields these filters read, so the
    /// tests check the jump arithmetic rather than restating it.
    fn run(prog: &Program, arch: u32, nr: u32, args: [u32; 2]) -> u32 {
        use super::super::bpf::{
            CODE_ALU_AND_K, CODE_JA, CODE_JEQ_K, CODE_JSET_K, CODE_LD_W_ABS, CODE_RET_K,
        };
        let insns = prog.insns();
        let mut pc = 0usize;
        let mut acc = 0u32;
        for _ in 0..4096 {
            let insn = insns[pc];
            match insn.code {
                CODE_LD_W_ABS => {
                    acc = match insn.k {
                        SD_ARCH => arch,
                        SD_NR => nr,
                        k if k == sd_arg_low(0) => args[0],
                        k if k == sd_arg_low(1) => args[1],
                        other => panic!("the filter read an unexpected offset {other}"),
                    };
                    pc += 1;
                }
                CODE_ALU_AND_K => {
                    acc &= insn.k;
                    pc += 1;
                }
                CODE_JEQ_K => {
                    pc += 1 + usize::from(if acc == insn.k { insn.jt } else { insn.jf });
                }
                CODE_JSET_K => {
                    pc += 1 + usize::from(if acc & insn.k != 0 { insn.jt } else { insn.jf });
                }
                CODE_JA => pc += 1 + insn.k as usize,
                CODE_RET_K => return insn.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
            assert!(pc < insns.len(), "jumped past the program");
        }
        panic!("the filter did not terminate");
    }

    const EPERM: u32 = SECCOMP_RET_ERRNO | LINUX_EPERM;
    const ENOSYS: u32 = SECCOMP_RET_ERRNO | LINUX_ENOSYS;
    const X86: u32 = AUDIT_ARCH_X86_64;
    /// Non-native ABIs the reference host accepts or could: i386, aarch64,
    /// 32-bit arm, garbage.
    const FOREIGN: [u32; 5] = [0x4000_0003, 0xc000_00b7, 0x4000_0028, 0, 0xffff_ffff];

    #[test]
    fn the_tool_baseline_is_byte_for_byte_the_checked_in_one() {
        // The shared builder must not have moved a single instruction of the
        // `tool` filter J2 verified: its digest is pinned by the evidence
        // file the conformance run compares, checked here on every host.
        let checked_in = include_str!(
            "../../../../../docs/specs/jail-v1/evidence/seccomp-table-tool-x86_64.txt"
        );
        assert_eq!(tool_baseline_table(), checked_in);
    }

    #[test]
    fn both_agent_variants_and_the_mediation_filter_assemble_and_differ() {
        let unpriv = agent_baseline(AgentVariant::UnprivilegedInner).unwrap();
        let ns = agent_baseline(AgentVariant::NamespaceInner).unwrap();
        let tool = tool_baseline().unwrap();
        let mediation = mediation_filter().unwrap();
        let digests = [
            tool.digest(),
            unpriv.digest(),
            ns.digest(),
            mediation.digest(),
        ];
        for (i, left) in digests.iter().enumerate() {
            for right in &digests[i + 1..] {
                assert_ne!(left, right, "two filters share a digest");
            }
        }
        for prog in [&unpriv, &ns, &mediation] {
            assert_eq!(prog.insns()[0].k, SD_ARCH, "architecture is checked first");
        }
    }

    #[test]
    fn the_unprivileged_agent_baseline_is_tool_without_the_af_unix_rule() {
        let agent = agent_baseline(AgentVariant::UnprivilegedInner).unwrap();
        let tool = tool_baseline().unwrap();
        // Every syscall tool denies, agent denies the same way, except AF_UNIX
        // socket creation, which the mediation filter owns.
        for (name, nr) in DENY_EPERM {
            assert_eq!(run(&agent, X86, *nr, [0, 0]), EPERM, "{name}");
            assert_eq!(run(&tool, X86, *nr, [0, 0]), EPERM, "{name}");
        }
        assert_eq!(run(&agent, X86, NR_CLONE3, [0, 0]), ENOSYS);
        assert_eq!(run(&agent, X86, NR_CLONE, [CLONE_NEWUSER_BIT, 0]), EPERM);
        assert_eq!(
            run(&agent, X86, NR_CLONE, [0x0001_0f00, 0]),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(run(&agent, X86, NR_IOCTL, [0, TIOCSTI]), EPERM);
        assert_eq!(run(&tool, X86, NR_SOCKET, [AF_UNIX, SOCK_STREAM]), EPERM);
        assert_eq!(
            run(&agent, X86, NR_SOCKET, [AF_UNIX, SOCK_STREAM]),
            SECCOMP_RET_ALLOW,
            "the agent baseline leaves AF_UNIX to the mediation filter"
        );
        // The unprivileged inner sandbox: no_new_privs (prctl 157), seccomp
        // (317) and the three Landlock calls (444-446) are allowed.
        for nr in [157, 317, 444, 445, 446] {
            assert_eq!(run(&agent, X86, nr, [0, 0]), SECCOMP_RET_ALLOW, "nr {nr}");
        }
        for arch in FOREIGN {
            for nr in [NR_CONNECT, NR_SOCKET, 1, 11, 102] {
                assert_eq!(run(&agent, arch, nr, [0, 0]), EPERM, "{arch:#x}/{nr}");
            }
        }
        assert_eq!(run(&agent, X86, X32_SYSCALL_BIT | 59, [0, 0]), EPERM);
    }

    const CLONE_NEWUSER_BIT: u32 = 0x1000_0000;

    #[test]
    fn the_namespace_variant_permits_only_the_namespace_setup() {
        let ns = agent_baseline(AgentVariant::NamespaceInner).unwrap();
        for (name, nr) in NAMESPACE_SETUP {
            assert_eq!(run(&ns, X86, nr, [0, 0]), SECCOMP_RET_ALLOW, "{name}");
        }
        assert_eq!(
            run(&ns, X86, NR_CLONE, [CLONE_NS_MASK, 0]),
            SECCOMP_RET_ALLOW
        );
        for (name, nr) in DENY_EPERM {
            if NAMESPACE_SETUP.iter().any(|(setup, _)| setup == name) {
                continue;
            }
            assert_eq!(run(&ns, X86, *nr, [0, 0]), EPERM, "{name} stays denied");
        }
        // setns, the new mount API and clone3 are never part of it.
        for nr in [308, 428, 429, 430, 431, 432, 433, 442] {
            assert_eq!(run(&ns, X86, nr, [0, 0]), EPERM, "nr {nr}");
        }
        assert_eq!(run(&ns, X86, NR_CLONE3, [0, 0]), ENOSYS);
        for arch in FOREIGN {
            assert_eq!(run(&ns, arch, 165, [0, 0]), EPERM, "{arch:#x}");
        }
        assert_eq!(
            AgentVariant::for_nested_user_namespace(true),
            AgentVariant::NamespaceInner
        );
        assert_eq!(
            AgentVariant::for_nested_user_namespace(false),
            AgentVariant::UnprivilegedInner
        );
        let ops = AgentVariant::NamespaceInner.allowed_setup_operations();
        assert!(ops.contains(&"unshare") && ops.contains(&"landlock_restrict_self"));
        assert!(
            !AgentVariant::UnprivilegedInner
                .allowed_setup_operations()
                .contains(&"mount")
        );
    }

    #[test]
    fn the_mediation_filter_notifies_connect_and_admits_only_stream_af_unix() {
        let m = mediation_filter().unwrap();
        assert_eq!(run(&m, X86, NR_CONNECT, [0, 0]), SECCOMP_RET_USER_NOTIF);
        for ty in [2, 3, 2 | 0x80000, 3 | 0x800, 4, 6, 10] {
            assert_eq!(
                run(&m, X86, NR_SOCKET, [AF_UNIX, ty]),
                EPERM,
                "type {ty:#x}"
            );
            assert_eq!(
                run(&m, X86, NR_SOCKETPAIR, [AF_UNIX, ty]),
                EPERM,
                "type {ty:#x}"
            );
        }
        for ty in [SOCK_STREAM, SOCK_SEQPACKET, SOCK_STREAM | 0x80000 | 0x800] {
            assert_eq!(
                run(&m, X86, NR_SOCKET, [AF_UNIX, ty]),
                SECCOMP_RET_ALLOW,
                "type {ty:#x}"
            );
        }
        assert_eq!(
            run(&m, X86, NR_SOCKET, [2, 2]),
            SECCOMP_RET_ALLOW,
            "AF_INET dgram"
        );
        assert_eq!(run(&m, X86, 1, [0, 0]), SECCOMP_RET_ALLOW);
        for arch in FOREIGN {
            for nr in [NR_CONNECT, NR_SOCKET, 102, 362] {
                assert_eq!(run(&m, arch, nr, [AF_UNIX, 2]), EPERM, "{arch:#x}/{nr}");
            }
        }
        assert_eq!(run(&m, X86, X32_SYSCALL_BIT | NR_CONNECT, [0, 0]), EPERM);
        assert!(
            m.disassemble()
                .iter()
                .any(|line| line.contains("and   #0x0000000f"))
        );
    }

    #[test]
    fn the_agent_table_names_every_rule_and_both_digests() {
        for variant in [
            AgentVariant::UnprivilegedInner,
            AgentVariant::NamespaceInner,
        ] {
            let table = agent_baseline_table(variant);
            assert!(table.contains(variant.as_str()));
            assert!(table.contains(&agent_baseline(variant).unwrap().digest()));
            assert!(table.contains(&mediation_filter().unwrap().digest()));
            for (name, _) in DENY_EPERM {
                assert!(table.contains(name), "{name}");
            }
            for name in UNPRIVILEGED_SETUP {
                assert!(table.contains(name), "{name}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_spelled_out_errnos_match_this_kernel() {
        assert_eq!(LINUX_EPERM, u32::try_from(libc::EPERM).unwrap());
        assert_eq!(LINUX_ENOSYS, u32::try_from(libc::ENOSYS).unwrap());
    }
}
