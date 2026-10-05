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
/// child's own `SECCOMP_RET_TRACE` — and is continued, counted in
/// `requested_by_other_filters` (audit 3 A5: the receipt carries the count,
/// so it is not silent), never mislabelled; one carrying this value for such
/// a number means the installed program is not this one, and is a visible
/// `unexpected_trace_stop` gap.
pub const NARROWING_TRACE_DATA: u16 = 0x4f4a;

/// Native `seccomp(2)`: a stop when its flags ask for a listener.
pub const LISTENER_SYSCALL: (&str, u32) = ("seccomp", crate::platform::linux::seccomp::NR_SECCOMP);
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;
/// Native `clone(2)`: a stop when its flags carry `CLONE_UNTRACED`.
pub const CLONE_SYSCALL: (&str, u32) = ("clone", crate::platform::linux::seccomp::NR_CLONE);
/// `CLONE_UNTRACED`: the kernel does not attach the new task to a tracer.
pub const CLONE_UNTRACED: u32 = 0x0080_0000;
/// `clone3(2)` on both native ABIs: refused with `ENOSYS`, since its flags are in
/// memory the filter cannot read.
pub const CLONE3_SYSCALL: (&str, u32) = ("clone3", 435);

/// Security 2026-09-27 (audit 4 B2): the i386 (`int 0x80`) numbers of the
/// two calls whose *native* forms get their own classification. A compat-ABI
/// entry carrying them must reach the same open-ended gaps, not the bounded
/// `foreign_abi` interval the plain foreign classification records — the
/// reference host does accept `int 0x80`, and under `none` a listener created
/// through it can pass any syscall with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
/// and no trace stop at all. The flags live in `args[1]` (seccomp) and
/// `args[0]` (clone) in that ABI too: the register positions are identical.
pub const I386_LISTENER_SYSCALL: u32 = 354;
/// i386 `clone`: same `CLONE_UNTRACED` flag semantics as the native number.
pub const I386_CLONE_SYSCALL: u32 = 120;

/// Instruction count: architecture check (2), x32 check (2), one comparison
/// per closed-set number, the listener check (3), the untraced-clone check
/// (3), the `clone3` check (1) and the three returns.
const FILTER_LEN: usize = CLOSED_SET.len() + 21;

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
/// Audit 2026-09-25-2, S14: `data` is the per-attempt `SECCOMP_RET_DATA`
/// the tracer expects; the canonical builder below keeps the frozen
/// evidence value.
fn build_into(out: &mut [libc::sock_filter; FILTER_LEN], data: u16, learning: bool) -> usize {
    let n = CLOSED_SET.len();
    let listener = n + 7;
    let clone = n + 10;
    let clone3 = n + 13;
    let open = n + 14;
    let openat = open + 2;
    let allow = n + 14 + if learning { 0 } else { 4 };
    let trace = allow + 1;
    let enosys = allow + 2;
    debug_assert!(n <= 235);
    // clone3's flags live behind a pointer on native, i386 and x32 alike.
    // Refuse it before the architecture branch, including the x32 spelling.
    out[0] = stmt(sys::BPF_LD_W_ABS, sys::SECCOMP_DATA_NR);
    out[1] = jump(sys::BPF_JEQ_K, 435, (enosys - 2) as u8, 0);
    out[2] = jump(
        sys::BPF_JEQ_K,
        435 | sys::X32_SYSCALL_BIT,
        (enosys - 3) as u8,
        0,
    );
    out[3] = stmt(sys::BPF_LD_W_ABS, sys::SECCOMP_DATA_ARCH);
    out[4] = jump(sys::BPF_JEQ_K, sys::AUDIT_ARCH, 0, (trace - 5) as u8);
    out[5] = stmt(sys::BPF_LD_W_ABS, sys::SECCOMP_DATA_NR);
    out[6] = jump(sys::BPF_JSET_K, sys::X32_SYSCALL_BIT, (trace - 7) as u8, 0);
    for (i, entry) in CLOSED_SET.iter().enumerate() {
        let destination = match (learning, entry.nr) {
            (false, _) if entry.name == "open" => open,
            (false, _) if entry.name == "openat" => openat,
            _ => trace,
        };
        out[7 + i] = jump(
            sys::BPF_JEQ_K,
            entry.nr as u32,
            (destination - 8 - i) as u8,
            0,
        );
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
        (allow - clone3 - 1) as u8,
    );
    if !learning {
        // open/openat flags are int arguments copied into seccomp_data by
        // the kernel. Unlike openat2's mutable open_how, there is no tracee
        // memory to race. Keep every write/create/truncate/tmpfile intent,
        // including invalid combinations. O_DIRECTORY alone is read-only.
        let writes = (libc::O_ACCMODE
            | libc::O_CREAT
            | libc::O_TRUNC
            | (libc::O_TMPFILE & !libc::O_DIRECTORY)) as u32;
        for (offset, arg) in [
            (open, sys::SECCOMP_DATA_ARG1_LOW),
            (openat, sys::SECCOMP_DATA_ARG2_LOW),
        ] {
            out[offset] = stmt(sys::BPF_LD_W_ABS, arg);
            out[offset + 1] = jump(
                sys::BPF_JSET_K,
                writes,
                (trace - offset - 2) as u8,
                (allow - offset - 2) as u8,
            );
        }
    }
    out[allow] = stmt(sys::BPF_RET_K, sys::SECCOMP_RET_ALLOW);
    out[trace] = stmt(sys::BPF_RET_K, sys::SECCOMP_RET_TRACE | u32::from(data));
    out[enosys] = stmt(sys::BPF_RET_K, sys::SECCOMP_RET_ERRNO | sys::LINUX_ENOSYS);
    enosys + 1
}

/// The narrowing filter, as classic BPF.
///
/// Canonical full-observation (learning) program. Normal contained runs use
/// the read-only-open fast path; their receipt records the installed digest.
#[must_use]
pub fn narrowing_filter() -> Vec<libc::sock_filter> {
    narrowing_filter_with(NARROWING_TRACE_DATA)
}

/// The narrowing filter carrying `data`, the value a per-attempt install
/// chose (audit 2026-09-25-2, S14). The canonical form above is what the
/// evidence table and the freeze digest name.
#[must_use]
pub fn narrowing_filter_with(data: u16) -> Vec<libc::sock_filter> {
    narrowing_filter_for(data, true)
}

/// The installed program for a particular observation mode. Learning keeps
/// read-only opens; ordinary observation handles them entirely in the kernel.
#[must_use]
pub fn narrowing_filter_for(data: u16, learning: bool) -> Vec<libc::sock_filter> {
    let mut prog = [ZERO; FILTER_LEN];
    let len = build_into(&mut prog, data, learning);
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
    for insn in narrowing_filter_with(NARROWING_TRACE_DATA) {
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

/// Security 2026-09-27 (audit 4 B9): the bytes of the filter carrying
/// `data` — the same layout with that one immediate differing. The receipt
/// must name the bytes the launcher **installed**, and since audit
/// 2026-09-25-2 (S14) those carry a per-attempt value, so the canonical
/// digest alone no longer identifies the installed program.
#[must_use]
pub fn narrowing_filter_bytes_with(data: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(FILTER_LEN * 8);
    for insn in narrowing_filter_with(data) {
        out.extend_from_slice(&insn.code.to_le_bytes());
        out.push(insn.jt);
        out.push(insn.jf);
        out.extend_from_slice(&insn.k.to_le_bytes());
    }
    out
}

/// `sha256:<hex>` over [`narrowing_filter_bytes_with`]: the digest of the
/// program an attempt actually installed (audit 4 B9).
#[must_use]
pub fn narrowing_filter_digest_with(data: u16) -> String {
    format!("sha256:{}", sha256_hex(&narrowing_filter_bytes_with(data)))
}

/// Digest of the exact mode-specific installed instructions.
#[must_use]
pub fn narrowing_filter_digest_for(data: u16, learning: bool) -> String {
    let mut bytes = Vec::new();
    for insn in narrowing_filter_for(data, learning) {
        bytes.extend_from_slice(&insn.code.to_le_bytes());
        bytes.extend_from_slice(&[insn.jt, insn.jf]);
        bytes.extend_from_slice(&insn.k.to_le_bytes());
    }
    format!("sha256:{}", sha256_hex(&bytes))
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
    install_narrowing_filter_with(NARROWING_TRACE_DATA)
}

/// Install the narrowing filter carrying `data` (audit 2026-09-25-2, S14:
/// the value is chosen per attempt by the supervisor and read by the
/// launcher from a pipe, so neither the public constant nor any inherited
/// argument names it). Same guarantees as [`install_narrowing_filter`].
///
/// # Errors
/// The `errno` of whichever of the two calls failed.
pub fn install_narrowing_filter_with(data: u16) -> Result<(), i32> {
    install_narrowing_filter_for(data, true)
}

/// Install the mode-specific filter without allocating after fork.
///
/// # Errors
/// Returns the errno of the failed no_new_privs or seccomp call.
pub fn install_narrowing_filter_for(data: u16, learning: bool) -> Result<(), i32> {
    let mut prog = [ZERO; FILTER_LEN];
    let len = build_into(&mut prog, data, learning);
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

    /// Security 2026-09-27 (audit 4 B9): the installed-bytes digest names
    /// the program an attempt ran, which is the canonical program only when
    /// the attempt drew the canonical trace data.
    #[test]
    fn audit4_installed_digest_differs_with_the_trace_data() {
        assert_eq!(
            narrowing_filter_digest_with(NARROWING_TRACE_DATA),
            narrowing_filter_digest(),
            "the canonical data digests the canonical program"
        );
        let other = NARROWING_TRACE_DATA ^ 0xa5a5;
        assert_ne!(
            narrowing_filter_digest_with(other),
            narrowing_filter_digest(),
            "a per-attempt value changes the installed bytes"
        );
        // Exactly one immediate differs between the two byte images.
        let canonical = narrowing_filter_bytes();
        let installed = narrowing_filter_bytes_with(other);
        assert_eq!(canonical.len(), installed.len());
        let mut words = 0usize;
        for (left, right) in canonical.chunks(8).zip(installed.chunks(8)) {
            if left != right {
                words += 1;
            }
        }
        assert_eq!(words, 1, "only the RET_TRACE data word differs");
    }

    /// Run the program the way the kernel would, so the test checks the
    /// jump arithmetic rather than restating it. `arg0` and `arg1` are the
    /// low words of the first two arguments; the filter may read the second.
    fn interpret_full(arch: u32, nr: u32, arg0: u32, arg1: u32) -> u32 {
        interpret_mode(arch, nr, [arg0, arg1, 0], true)
    }

    fn interpret_mode(arch: u32, nr: u32, args: [u32; 3], learning: bool) -> u32 {
        const ARG0_LOW: u32 = 16;
        let prog = narrowing_filter_for(NARROWING_TRACE_DATA, learning);
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
                        args[0]
                    } else if insn.k == sys::SECCOMP_DATA_ARG1_LOW {
                        args[1]
                    } else if insn.k == 32 {
                        args[2]
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
        interpret_full(sys::AUDIT_ARCH, nr, 0, arg1)
    }

    const TRACE: u32 = sys::SECCOMP_RET_TRACE | NARROWING_TRACE_DATA as u32;

    #[test]
    fn fast_path_only_skips_register_sourced_read_only_opens() {
        let arch = sys::AUDIT_ARCH;
        let opens = if cfg!(target_arch = "aarch64") {
            vec![56]
        } else {
            vec![2, 257]
        };
        for nr in opens.iter().copied() {
            for flags in [
                0,
                libc::O_CLOEXEC,
                libc::O_DIRECTORY,
                libc::O_PATH | libc::O_DIRECTORY,
                libc::O_NONBLOCK | libc::O_NOFOLLOW,
            ] {
                let args = if nr == 2 {
                    [0, flags as u32, 0]
                } else {
                    [0, 0, flags as u32]
                };
                assert_eq!(
                    interpret_mode(arch, nr, args, false),
                    sys::SECCOMP_RET_ALLOW
                );
                assert_eq!(interpret_mode(arch, nr, args, true), TRACE);
            }
            for flags in [
                libc::O_WRONLY,
                libc::O_RDWR,
                libc::O_CREAT,
                libc::O_TRUNC,
                libc::O_TMPFILE,
                libc::O_ACCMODE,
                libc::O_PATH | libc::O_CREAT,
            ] {
                let args = if nr == 2 {
                    [0, flags as u32, 0]
                } else {
                    [0, 0, flags as u32]
                };
                assert_eq!(interpret_mode(arch, nr, args, false), TRACE);
            }
        }
        // Every other number and every ABI/gap path keeps its old verdict.
        for arch in [arch, 0x4000_0003] {
            for nr in (0..1024).chain((0..1024).map(|nr| nr | sys::X32_SYSCALL_BIT)) {
                if arch == sys::AUDIT_ARCH && opens.contains(&nr) {
                    continue;
                }
                for args in [[0; 3], [u32::MAX; 3]] {
                    assert_eq!(
                        interpret_mode(arch, nr, args, false),
                        interpret_mode(arch, nr, args, true),
                        "nr {nr}"
                    );
                }
            }
        }
        assert_ne!(
            narrowing_filter_digest_for(42, false),
            narrowing_filter_digest_for(42, true)
        );
        assert_eq!(
            narrowing_filter_digest_for(42, true),
            narrowing_filter_digest_with(42)
        );
    }

    /// J4 D2: without a containment baseline (`none`) nothing else refuses
    /// another ABI, so the narrowing filter stops on every syscall under a
    /// non-native architecture and on every x32 number; the tracer labels
    /// the stop foreign and never decodes it from this table. In contained
    /// profiles the baseline's `EPERM` outranks the trace, so no stop happens.
    #[test]
    fn j4_d2_every_foreign_abi_syscall_is_traced() {
        const AUDIT_ARCH_I386: u32 = 0x4000_0003;
        const OTHER_ARCH: u32 = if cfg!(target_arch = "aarch64") {
            0xc000_003e
        } else {
            0xc000_00b7
        };
        for arch in [AUDIT_ARCH_I386, OTHER_ARCH, 0, 0xffff_ffff] {
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
                interpret(sys::AUDIT_ARCH, sys::X32_SYSCALL_BIT | nr),
                TRACE,
                "x32 {nr:#x} must stop"
            );
        }
        // A number past the x32 range without its bit is a native number no
        // table has: the kernel answers ENOSYS, and this filter lets it by.
        assert_eq!(
            interpret(sys::AUDIT_ARCH, 0x8000_0000),
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
        const SECCOMP: u32 = LISTENER_SYSCALL.1;
        const PRCTL: u32 = crate::platform::linux::abi::nr(157, 167);
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
                interpret_full(sys::AUDIT_ARCH, PRCTL, option, NEW_LISTENER),
                sys::SECCOMP_RET_ALLOW,
                "prctl option {option}"
            );
        }
    }

    #[test]
    fn every_closed_set_number_traces_and_nothing_else_does() {
        for entry in CLOSED_SET {
            assert_eq!(
                interpret(sys::AUDIT_ARCH, entry.nr as u32),
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
                interpret(sys::AUDIT_ARCH, nr),
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
        const CLONE: u32 = CLONE_SYSCALL.1;
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
                interpret_full(sys::AUDIT_ARCH, CLONE, flags, 0),
                TRACE,
                "clone flags {flags:#x} must stop"
            );
        }
        for flags in [0, SIGCHLD, THREAD, VFORK, !CLONE_UNTRACED] {
            assert_eq!(
                interpret_full(sys::AUDIT_ARCH, CLONE, flags, 0),
                sys::SECCOMP_RET_ALLOW,
                "clone flags {flags:#x} carry no CLONE_UNTRACED"
            );
        }
        // The flag in another call's first argument means nothing.
        for nr in [57u32, 58, 1, 0] {
            assert_eq!(
                interpret_full(sys::AUDIT_ARCH, nr, CLONE_UNTRACED, 0),
                sys::SECCOMP_RET_ALLOW,
                "nr {nr}"
            );
        }
        for (arg0, arg1) in [(0, 0), (0x1000, 88), (u32::MAX, u32::MAX)] {
            assert_eq!(
                interpret_full(sys::AUDIT_ARCH, CLONE3_SYSCALL.1, arg0, arg1),
                ENOSYS
            );
        }
        // Compat clone3 is refused before architecture dispatch.
        assert_eq!(interpret(0x4000_0003, CLONE3_SYSCALL.1), ENOSYS);
        assert_eq!(
            interpret(sys::AUDIT_ARCH, CLONE3_SYSCALL.1 | sys::X32_SYSCALL_BIT),
            ENOSYS
        );
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
                interpret(sys::AUDIT_ARCH, nr as u32),
                sys::SECCOMP_RET_ALLOW,
                "syscall {nr} is outside the closed set"
            );
        }
    }

    #[test]
    fn the_program_is_the_expected_shape_and_refuses_only_clone3() {
        let prog = narrowing_filter();
        assert_eq!(prog.len(), CLOSED_SET.len() + 17);
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
            let verdict = interpret(sys::AUDIT_ARCH, nr);
            assert_eq!(verdict == ENOSYS, nr == CLONE3_SYSCALL.1, "nr {nr}");
        }
        assert_eq!(prog[0].code, sys::BPF_LD_W_ABS);
        assert_eq!(
            prog[0].k,
            sys::SECCOMP_DATA_NR,
            "compat clone3 is refused before architecture dispatch"
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
