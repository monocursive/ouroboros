//! The narrowing seccomp filter the launcher installs before it blocks on the
//! release pipe.
//!
//! It is not an enforcement filter. The bubblewrap baseline of jail-v1 §9.2
//! is installed separately and decides what is allowed; this one decides
//! what stops, and it refuses exactly one call, `clone3`, with the `ENOSYS` a
//! kernel without it would give. Four kinds of call return
//! `SECCOMP_RET_TRACE` (with [`NARROWING_TRACE_DATA`] in its data bits):
//!
//! * every number in `linux-closed-v1`, compared only after the architecture
//!   has been checked, because a number means nothing without it;
//! * every syscall under another architecture or with the x32 bit (J4 D2).
//!   The tracer never decodes these from the x86_64 table; it labels them
//!   foreign. In a contained profile the baseline's `EPERM` for those ABIs
//!   outranks the trace, so only `none` ever stops on one;
//! * `seccomp(2)` whose flags ask for `SECCOMP_FILTER_FLAG_NEW_LISTENER`
//!   (J4 D1). A child's own notification listener outranks this filter's
//!   trace, and a `CONTINUE` reply runs the call with no stop, so the tracer
//!   must learn that one exists. The flags are a register, which the filter
//!   reads directly; `tool` and `build` refuse the flag outright (EPERM);
//! * `clone(2)` whose flags carry `CLONE_UNTRACED` (J4 S4). The kernel does
//!   not attach such a child to the tracer, so the tracer must learn that
//!   one exists. The contained baselines refuse the flag (EPERM), which
//!   outranks the trace, so only `none` ever stops on one.
//!
//! `clone3` passes its flags in memory, which seccomp cannot read, so the
//! same question cannot be asked of it: it is refused with `ENOSYS`, as the
//! contained baselines already refuse it, and glibc falls back to `clone`
//! (jail-v1 §9.2). Everything else returns `SECCOMP_RET_ALLOW`.
//!
//! The filter is also the fail-closed property the supervisor relies on:
//! `SECCOMP_RET_TRACE` with no tracer attached does not run the syscall, it
//! fails it with `ENOSYS`. If the observer dies, closed-set operations stop
//! working rather than proceeding unobserved. `observer_linux.rs` proves it.
//! The same holds for a descendant created with `CLONE_UNTRACED`: its
//! closed-set calls fail with `ENOSYS`, because nothing traces it.

use crate::platform::linux::tracer::closed_set::CLOSED_SET;
use crate::platform::linux::tracer::digest::sha256_hex;
use crate::platform::linux::tracer::sys;

/// The `SECCOMP_RET_DATA` this filter's trace carries, which the tracer reads
/// back at a stop (`PTRACE_GETEVENTMSG`). A stop for a number this filter
/// does not trace, carrying other data, is one another filter asked for — a
/// child's own `SECCOMP_RET_TRACE` — and is continued, not mislabelled; one
/// carrying this value for such a number means the installed program is not
/// this one, and is a gap.
pub const NARROWING_TRACE_DATA: u16 = 0x4f4a;

/// `seccomp(2)` on x86_64: a stop when its flags ask for a listener.
pub const LISTENER_SYSCALL: (&str, u32) = ("seccomp", 317);
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;
/// `clone(2)` on x86_64: a stop when its flags carry `CLONE_UNTRACED`.
pub const CLONE_SYSCALL: (&str, u32) = ("clone", 56);
/// `CLONE_UNTRACED`: the kernel does not attach the new task to a tracer.
pub const CLONE_UNTRACED: u32 = 0x0080_0000;
/// `clone3(2)` on x86_64: refused with `ENOSYS`, since its flags are in
/// memory the filter cannot read.
pub const CLONE3_SYSCALL: (&str, u32) = ("clone3", 435);

/// Instruction count: architecture check (2), x32 check (2), one comparison
/// per closed-set number, the listener check (3), the untraced-clone check
/// (3), the `clone3` check (1) and the three returns.
const FILTER_LEN: usize = CLOSED_SET.len() + 14;

const ZERO: libc::sock_filter = libc::sock_filter {
    code: 0,
    jt: 0,
    jf: 0,
    k: 0,
};

const fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Write the program into `out` and return its length.
///
/// Allocation-free by construction, so [`install_narrowing_filter`] can run
/// between `fork` and `execve`.
fn build_into(out: &mut [libc::sock_filter; FILTER_LEN]) -> usize {
    let n = CLOSED_SET.len();
    let listener = n + 4;
    let clone = n + 7;
    let clone3 = n + 10;
    let allow = n + 11;
    let trace = n + 12;
    let enosys = n + 13;
    // Jump targets are relative to the instruction after the jump, so a jump
    // at `i` reaching `t` uses an offset of `t - i - 1`. Each fits in the u8
    // the cBPF encoding allows as long as the set stays under 240 rows.
    debug_assert!(n <= 240);
    out[0] = stmt(sys::BPF_LD_W_ABS, sys::SECCOMP_DATA_ARCH);
    // Not x86_64: stop. Nothing here decodes another architecture's table,
    // so the tracer labels the stop foreign; where a baseline is installed,
    // its EPERM for any other architecture outranks this and nothing stops.
    out[1] = jump(sys::BPF_JEQ_K, sys::AUDIT_ARCH_X86_64, 0, (trace - 2) as u8);
    out[2] = stmt(sys::BPF_LD_W_ABS, sys::SECCOMP_DATA_NR);
    // x32 sets bit 30 of nr on the x86_64 architecture value. Its numbers are
    // a different table: stop, and let the tracer label it foreign rather
    // than match it against this one.
    out[3] = jump(sys::BPF_JSET_K, sys::X32_SYSCALL_BIT, (trace - 4) as u8, 0);
    for (i, entry) in CLOSED_SET.iter().enumerate() {
        out[4 + i] = jump(sys::BPF_JEQ_K, entry.nr as u32, (trace - 5 - i) as u8, 0);
    }
    // seccomp(2) asking for a notification listener. Its flags are an
    // `unsigned int`, so the low word of the second argument is all of them.
    // Any other number goes on to the clone check with the number still in
    // the accumulator.
    out[listener] = jump(
        sys::BPF_JEQ_K,
        LISTENER_SYSCALL.1,
        0,
        (clone - listener - 1) as u8,
    );
    out[listener + 1] = stmt(sys::BPF_LD_W_ABS, sys::SECCOMP_DATA_ARG1_LOW);
    out[listener + 2] = jump(
        sys::BPF_JSET_K,
        SECCOMP_FILTER_FLAG_NEW_LISTENER,
        (trace - listener - 3) as u8,
        (allow - listener - 3) as u8,
    );
    // clone(2) with CLONE_UNTRACED. Every clone flag lives in the low word
    // of the first argument on x86_64.
    out[clone] = jump(
        sys::BPF_JEQ_K,
        CLONE_SYSCALL.1,
        0,
        (clone3 - clone - 1) as u8,
    );
    out[clone + 1] = stmt(sys::BPF_LD_W_ABS, sys::SECCOMP_DATA_ARG0_LOW);
    out[clone + 2] = jump(
        sys::BPF_JSET_K,
        CLONE_UNTRACED,
        (trace - clone - 3) as u8,
        (allow - clone - 3) as u8,
    );
    // clone3(2): its flags are behind a pointer. ENOSYS, and glibc falls back.
    out[clone3] = jump(
        sys::BPF_JEQ_K,
        CLONE3_SYSCALL.1,
        (enosys - clone3 - 1) as u8,
        0,
    );
    out[allow] = stmt(sys::BPF_RET_K, sys::SECCOMP_RET_ALLOW);
    out[trace] = stmt(
        sys::BPF_RET_K,
        sys::SECCOMP_RET_TRACE | u32::from(NARROWING_TRACE_DATA),
    );
    out[enosys] = stmt(sys::BPF_RET_K, sys::SECCOMP_RET_ERRNO | sys::LINUX_ENOSYS);
    FILTER_LEN
}

/// The narrowing filter, as classic BPF.
///
/// The launcher installs exactly these instructions; the digest below names
/// exactly these bytes.
#[must_use]
pub fn narrowing_filter() -> Vec<libc::sock_filter> {
    let mut prog = [ZERO; FILTER_LEN];
    let len = build_into(&mut prog);
    prog[..len].to_vec()
}

/// The bytes the digest is taken over: each instruction as
/// `code` (little-endian u16), `jt`, `jf`, `k` (little-endian u32).
///
/// Written out rather than reinterpreted from the struct so the digest names
/// the same bytes on any host, not the padding of one ABI.
#[must_use]
pub fn narrowing_filter_bytes() -> Vec<u8> {
    let mut out = Vec::with_capacity(FILTER_LEN * 8);
    for insn in narrowing_filter() {
        out.extend_from_slice(&insn.code.to_le_bytes());
        out.push(insn.jt);
        out.push(insn.jf);
        out.extend_from_slice(&insn.k.to_le_bytes());
    }
    out
}

/// `sha256:<hex>` over [`narrowing_filter_bytes`].
#[must_use]
pub fn narrowing_filter_digest() -> String {
    format!("sha256:{}", sha256_hex(&narrowing_filter_bytes()))
}

/// Install the narrowing filter on the calling thread group.
///
/// Async-signal-safe: it allocates nothing, takes no lock and touches no
/// global state. The program is built into a stack array from a `const`
/// table, and the two calls are `prctl(PR_SET_NO_NEW_PRIVS)` and
/// `seccomp(SECCOMP_SET_MODE_FILTER)`. This is what a launcher may call
/// between `fork` and `execve`.
///
/// # Errors
/// The `errno` of whichever of the two calls failed. `EACCES` means
/// `no_new_privs` was not set; `EINVAL` means the kernel rejected the
/// program.
///
/// # Warning
/// After this returns, every closed-set syscall made by this process or any
/// descendant fails with `ENOSYS` until a tracer is attached. Install it and
/// then block; do not open a file in between.
pub fn install_narrowing_filter() -> Result<(), i32> {
    let mut prog = [ZERO; FILTER_LEN];
    let len = build_into(&mut prog);
    let fprog = libc::sock_fprog {
        len: len as u16,
        filter: prog.as_mut_ptr(),
    };
    // SAFETY: `prctl` with PR_SET_NO_NEW_PRIVS takes four integer arguments
    // and dereferences nothing.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        // SAFETY: errno for this thread.
        return Err(unsafe { *libc::__errno_location() });
    }
    // SAFETY: `seccomp(SECCOMP_SET_MODE_FILTER, 0, &fprog)` reads one
    // `sock_fprog` and the `len` instructions it points at. `fprog` and
    // `prog` are both live for the whole call and `len` is the length of
    // `prog`, which `build_into` just filled.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            sys::SECCOMP_SET_MODE_FILTER,
            0,
            (&raw const fprog).cast::<libc::c_void>(),
        )
    };
    if rc != 0 {
        // SAFETY: errno for this thread.
        return Err(unsafe { *libc::__errno_location() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::tracer::closed_set::lookup;

    /// Run the program the way the kernel would, so the test checks the
    /// jump arithmetic rather than restating it. `arg0` and `arg1` are the
    /// low words of the first two arguments; the filter may read the second.
    fn interpret_full(arch: u32, nr: u32, arg0: u32, arg1: u32) -> u32 {
        const ARG0_LOW: u32 = 16;
        let prog = narrowing_filter();
        let mut pc = 0usize;
        let mut acc: u32 = 0;
        for _ in 0..4096 {
            let insn = prog[pc];
            match insn.code {
                c if c == sys::BPF_LD_W_ABS => {
                    acc = if insn.k == sys::SECCOMP_DATA_NR {
                        nr
                    } else if insn.k == sys::SECCOMP_DATA_ARCH {
                        arch
                    } else if insn.k == ARG0_LOW {
                        arg0
                    } else if insn.k == sys::SECCOMP_DATA_ARG1_LOW {
                        arg1
                    } else {
                        panic!(
                            "the filter must only read nr, arch and the second argument, not offset {}",
                            insn.k
                        )
                    };
                    pc += 1;
                }
                c if c == sys::BPF_JEQ_K => {
                    pc += 1 + usize::from(if acc == insn.k { insn.jt } else { insn.jf });
                }
                c if c == sys::BPF_JSET_K => {
                    pc += 1 + usize::from(if acc & insn.k != 0 { insn.jt } else { insn.jf });
                }
                c if c == sys::BPF_RET_K => return insn.k,
                other => panic!("unknown opcode {other:#x}"),
            }
            assert!(pc < prog.len(), "jumped past the end of the program");
        }
        panic!("the filter must terminate");
    }

    fn interpret(arch: u32, nr: u32) -> u32 {
        interpret_full(arch, nr, 0, 0)
    }

    fn interpret_flags(nr: u32, arg1: u32) -> u32 {
        interpret_full(sys::AUDIT_ARCH_X86_64, nr, 0, arg1)
    }

    const TRACE: u32 = sys::SECCOMP_RET_TRACE | NARROWING_TRACE_DATA as u32;

    /// J4 D2: without a containment baseline (`none`) nothing else refuses
    /// another ABI, so the narrowing filter stops on every syscall under a
    /// non-native architecture and on every x32 number; the tracer labels
    /// the stop foreign and never decodes it from this table. In contained
    /// profiles the baseline's `EPERM` outranks the trace, so no stop happens.
    #[test]
    fn j4_d2_every_foreign_abi_syscall_is_traced() {
        const AUDIT_ARCH_I386: u32 = 0x4000_0003;
        const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
        for arch in [AUDIT_ARCH_I386, AUDIT_ARCH_AARCH64, 0, 0xffff_ffff] {
            for nr in [0u32, 2, 5, 11, 39, 42, 157, 257, 317, 322, 0x7ffe] {
                assert_eq!(
                    interpret(arch, nr),
                    TRACE,
                    "arch {arch:#x} nr {nr} must stop"
                );
            }
        }
        for nr in [0u32, 1, 39, 42, 59, 257, 0x3fff_ffff] {
            assert_eq!(
                interpret(sys::AUDIT_ARCH_X86_64, sys::X32_SYSCALL_BIT | nr),
                TRACE,
                "x32 {nr:#x} must stop"
            );
        }
        // A number past the x32 range without its bit is a native number no
        // table has: the kernel answers ENOSYS, and this filter lets it by.
        assert_eq!(
            interpret(sys::AUDIT_ARCH_X86_64, 0x8000_0000),
            sys::SECCOMP_RET_ALLOW
        );
    }

    /// J4 D1: every observed profile stops on `seccomp(2)` asking for a
    /// notification listener — the one filter shape that can let a
    /// closed-set call take effect with no trace stop (integrator decision
    /// S3) — and on nothing else of the seccomp interface: a plain filter,
    /// the query operations and `prctl(PR_SET_SECCOMP)`, which cannot ask
    /// for a listener, run untraced.
    #[test]
    fn j4_d1_a_listener_request_is_traced() {
        const SECCOMP: u32 = 317;
        const PRCTL: u32 = 157;
        const NEW_LISTENER: u32 = 1 << 3;
        const TSYNC: u32 = 1;
        const TSYNC_ESRCH: u32 = 1 << 4;
        for flags in [
            NEW_LISTENER,
            NEW_LISTENER | TSYNC | TSYNC_ESRCH,
            0xffff_ffff,
        ] {
            assert_eq!(
                interpret_flags(SECCOMP, flags),
                TRACE,
                "seccomp flags {flags:#x} must stop"
            );
        }
        for flags in [0, TSYNC, 1 << 2, TSYNC_ESRCH] {
            assert_eq!(
                interpret_flags(SECCOMP, flags),
                sys::SECCOMP_RET_ALLOW,
                "seccomp flags {flags:#x} asks for no listener"
            );
        }
        // PR_SET_SECCOMP, PR_SET_NAME, PR_SET_NO_NEW_PRIVS.
        for option in [22u32, 15, 38] {
            assert_eq!(
                interpret_full(sys::AUDIT_ARCH_X86_64, PRCTL, option, NEW_LISTENER),
                sys::SECCOMP_RET_ALLOW,
                "prctl option {option}"
            );
        }
    }

    #[test]
    fn every_closed_set_number_traces_and_nothing_else_does() {
        for entry in CLOSED_SET {
            assert_eq!(
                interpret(sys::AUDIT_ARCH_X86_64, entry.nr as u32),
                TRACE,
                "{} ({}) must stop",
                entry.name,
                entry.nr
            );
        }
        for nr in 0u32..600 {
            let expected = if lookup(u64::from(nr)).is_some() {
                TRACE
            } else if nr == CLONE3_SYSCALL.1 {
                ENOSYS
            } else {
                sys::SECCOMP_RET_ALLOW
            };
            assert_eq!(
                interpret(sys::AUDIT_ARCH_X86_64, nr),
                expected,
                "syscall {nr} with no listener or untraced flag"
            );
        }
    }

    const ENOSYS: u32 = sys::SECCOMP_RET_ERRNO | sys::LINUX_ENOSYS;

    /// J4 S4: `clone` stops when its flags carry `CLONE_UNTRACED`, whatever
    /// else they carry, and runs untouched otherwise — the flags glibc uses
    /// for threads, `fork` and `posix_spawn` included. `clone3` is refused
    /// with ENOSYS whatever its (unreadable) arguments, and nothing else is.
    #[test]
    fn j4_s4_an_untraced_clone_stops_and_clone3_is_enosys() {
        const CLONE: u32 = 56;
        const SIGCHLD: u32 = 17;
        const THREAD: u32 = 0x003d_0f00;
        const VFORK: u32 = 0x0000_4100 | SIGCHLD;
        for flags in [
            CLONE_UNTRACED,
            CLONE_UNTRACED | SIGCHLD,
            CLONE_UNTRACED | THREAD,
            CLONE_UNTRACED | VFORK,
            0xffff_ffff,
        ] {
            assert_eq!(
                interpret_full(sys::AUDIT_ARCH_X86_64, CLONE, flags, 0),
                TRACE,
                "clone flags {flags:#x} must stop"
            );
        }
        for flags in [0, SIGCHLD, THREAD, VFORK, !CLONE_UNTRACED] {
            assert_eq!(
                interpret_full(sys::AUDIT_ARCH_X86_64, CLONE, flags, 0),
                sys::SECCOMP_RET_ALLOW,
                "clone flags {flags:#x} carry no CLONE_UNTRACED"
            );
        }
        // The flag in another call's first argument means nothing.
        for nr in [57u32, 58, 1, 0] {
            assert_eq!(
                interpret_full(sys::AUDIT_ARCH_X86_64, nr, CLONE_UNTRACED, 0),
                sys::SECCOMP_RET_ALLOW,
                "nr {nr}"
            );
        }
        for (arg0, arg1) in [(0, 0), (0x1000, 88), (u32::MAX, u32::MAX)] {
            assert_eq!(
                interpret_full(sys::AUDIT_ARCH_X86_64, CLONE3_SYSCALL.1, arg0, arg1),
                ENOSYS
            );
        }
        // Another ABI's clone3 number is foreign, not refused: it stops.
        assert_eq!(interpret(0x4000_0003, CLONE3_SYSCALL.1), TRACE);
        assert_eq!(
            (CLONE_SYSCALL.1, CLONE3_SYSCALL.1, CLONE_UNTRACED),
            (libc::SYS_clone as u32, 435, libc::CLONE_UNTRACED as u32)
        );
    }

    #[test]
    fn read_write_and_mmap_are_allowed_through() {
        for nr in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_mmap,
            libc::SYS_close,
        ] {
            assert_eq!(
                interpret(sys::AUDIT_ARCH_X86_64, nr as u32),
                sys::SECCOMP_RET_ALLOW,
                "syscall {nr} is outside the closed set"
            );
        }
    }

    #[test]
    fn the_program_is_the_expected_shape_and_refuses_only_clone3() {
        let prog = narrowing_filter();
        assert_eq!(prog.len(), CLOSED_SET.len() + 14);
        for insn in &prog {
            if insn.code == sys::BPF_RET_K {
                assert!(
                    insn.k == sys::SECCOMP_RET_ALLOW || insn.k == TRACE || insn.k == ENOSYS,
                    "the narrowing filter never denies anything but clone3: {:#x}",
                    insn.k
                );
            }
        }
        // And the one refusal is reached by clone3 alone.
        for nr in 0u32..1024 {
            let verdict = interpret(sys::AUDIT_ARCH_X86_64, nr);
            assert_eq!(verdict == ENOSYS, nr == CLONE3_SYSCALL.1, "nr {nr}");
        }
        assert_eq!(prog[0].code, sys::BPF_LD_W_ABS);
        assert_eq!(
            prog[0].k,
            sys::SECCOMP_DATA_ARCH,
            "the architecture is read first"
        );
    }

    #[test]
    fn the_digest_names_the_bytes_that_are_installed() {
        let bytes = narrowing_filter_bytes();
        assert_eq!(bytes.len(), narrowing_filter().len() * 8);
        let digest = narrowing_filter_digest();
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), "sha256:".len() + 64);
        assert_eq!(digest, narrowing_filter_digest(), "the digest is stable");
        assert_eq!(
            digest[7..],
            sha256_hex(&bytes),
            "and it is the digest of those bytes"
        );
        // A different program must produce a different digest.
        let mut altered = bytes.clone();
        altered[0] ^= 0xff;
        assert_ne!(sha256_hex(&altered), sha256_hex(&bytes));
    }
}
