//! The narrowing seccomp filter the launcher installs before it blocks on the
//! release pipe.
//!
//! It is not an enforcement filter. The bubblewrap baseline of jail-v1 §9.2
//! is installed separately and decides what is allowed; this one only decides
//! what stops. Every number in `linux-closed-v1` returns
//! `SECCOMP_RET_TRACE`, everything else returns `SECCOMP_RET_ALLOW`, and the
//! architecture is checked before any syscall number is compared, because a
//! number means nothing without it.
//!
//! The filter is also the fail-closed property the supervisor relies on:
//! `SECCOMP_RET_TRACE` with no tracer attached does not run the syscall, it
//! fails it with `ENOSYS`. If the observer dies, closed-set operations stop
//! working rather than proceeding unobserved. `observer_linux.rs` proves it.

use crate::platform::linux::tracer::closed_set::CLOSED_SET;
use crate::platform::linux::tracer::digest::sha256_hex;
use crate::platform::linux::tracer::sys;

/// Instruction count: architecture check (2), x32 check (2), one comparison
/// per closed-set number, and the two return instructions.
const FILTER_LEN: usize = CLOSED_SET.len() + 6;

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
    let allow = n + 4;
    let trace = n + 5;
    // Jump targets are relative to the instruction after the jump, so a jump
    // at `i` reaching `t` uses an offset of `t - i - 1`. Each fits in the u8
    // the cBPF encoding allows as long as the set stays under 250 rows.
    debug_assert!(n <= 250);
    out[0] = stmt(sys::BPF_LD_W_ABS, sys::SECCOMP_DATA_ARCH);
    // Not x86_64: allow through, so the baseline filter's own architecture
    // check is what denies it. This filter never denies anything.
    out[1] = jump(sys::BPF_JEQ_K, sys::AUDIT_ARCH_X86_64, 0, (allow - 2) as u8);
    out[2] = stmt(sys::BPF_LD_W_ABS, sys::SECCOMP_DATA_NR);
    // x32 sets bit 30 of nr on the x86_64 architecture value. Its numbers are
    // a different table, so tracing them against this one would mislabel
    // calls; they go to the baseline denial untouched.
    out[3] = jump(sys::BPF_JGE_K, sys::X32_SYSCALL_BIT, (allow - 4) as u8, 0);
    for (i, entry) in CLOSED_SET.iter().enumerate() {
        out[4 + i] = jump(sys::BPF_JEQ_K, entry.nr as u32, (n - i) as u8, 0);
    }
    out[allow] = stmt(sys::BPF_RET_K, sys::SECCOMP_RET_ALLOW);
    out[trace] = stmt(sys::BPF_RET_K, sys::SECCOMP_RET_TRACE);
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
    /// jump arithmetic rather than restating it.
    fn interpret(arch: u32, nr: u32) -> u32 {
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
                    } else {
                        panic!(
                            "the filter must only read nr and arch, not offset {}",
                            insn.k
                        )
                    };
                    pc += 1;
                }
                c if c == sys::BPF_JEQ_K => {
                    pc += 1 + usize::from(if acc == insn.k { insn.jt } else { insn.jf });
                }
                c if c == sys::BPF_JGE_K => {
                    pc += 1 + usize::from(if acc >= insn.k { insn.jt } else { insn.jf });
                }
                c if c == sys::BPF_RET_K => return insn.k,
                other => panic!("unknown opcode {other:#x}"),
            }
            assert!(pc < prog.len(), "jumped past the end of the program");
        }
        panic!("the filter must terminate");
    }

    #[test]
    fn every_closed_set_number_traces_and_nothing_else_does() {
        for entry in CLOSED_SET {
            assert_eq!(
                interpret(sys::AUDIT_ARCH_X86_64, entry.nr as u32),
                sys::SECCOMP_RET_TRACE,
                "{} ({}) must stop",
                entry.name,
                entry.nr
            );
        }
        for nr in 0u32..600 {
            let expected = if lookup(u64::from(nr)).is_some() {
                sys::SECCOMP_RET_TRACE
            } else {
                sys::SECCOMP_RET_ALLOW
            };
            assert_eq!(
                interpret(sys::AUDIT_ARCH_X86_64, nr),
                expected,
                "syscall {nr}"
            );
        }
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
    fn another_architecture_is_allowed_through_to_the_baseline() {
        const AUDIT_ARCH_I386: u32 = 0x4000_0003;
        const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
        for arch in [AUDIT_ARCH_I386, AUDIT_ARCH_AARCH64, 0, 0xffff_ffff] {
            for nr in [0u32, 2, 42, 257, 322] {
                assert_eq!(
                    interpret(arch, nr),
                    sys::SECCOMP_RET_ALLOW,
                    "arch {arch:#x} must not be matched against x86_64 numbers"
                );
            }
        }
    }

    #[test]
    fn x32_is_allowed_through_to_the_baseline() {
        // x32 openat is 0x40000000 | 257; tracing it against the x86_64
        // table would label a different syscall.
        for nr in [257u32, 59, 42] {
            assert_eq!(
                interpret(sys::AUDIT_ARCH_X86_64, sys::X32_SYSCALL_BIT | nr),
                sys::SECCOMP_RET_ALLOW,
                "x32 {nr} must not be traced"
            );
        }
    }

    #[test]
    fn the_program_is_the_expected_shape_and_never_denies() {
        let prog = narrowing_filter();
        assert_eq!(prog.len(), CLOSED_SET.len() + 6);
        for insn in &prog {
            if insn.code == sys::BPF_RET_K {
                assert!(
                    insn.k == sys::SECCOMP_RET_ALLOW || insn.k == sys::SECCOMP_RET_TRACE,
                    "the narrowing filter never denies: {:#x}",
                    insn.k
                );
            }
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
