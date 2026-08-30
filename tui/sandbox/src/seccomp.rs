//! The seccomp belt.
//!
//! # Intent
//!
//! This filter is **not** the containment. The mount policy and the Landlock domain are.
//! What it does is remove a short list of syscalls that no compiler, test runner, or
//! package manager has any reason to make, and that would each undo part of the other two
//! layers if they succeeded:
//!
//!   * **mount / umount2 / pivot_root / chroot / the whole `fsopen`-era mount API** — a
//!     process that has just created its own user namespace holds `CAP_SYS_ADMIN` in it.
//!     The helper drops that capability before exec, but a denial in the kernel is worth
//!     more than a capability the helper believes it dropped.
//!   * **setns / unshare** — otherwise a command creates a fresh user namespace, gets a
//!     full capability set in it, and starts again on the point above. (A Landlock domain
//!     is inherited across all of it and cannot be escaped this way; this closes the
//!     mount half.)
//!   * **init_module / finit_module / delete_module / kexec_*** — kernel text.
//!   * **bpf / perf_event_open** — kernel-side programs and system-wide tracing.
//!   * **add_key / keyctl / request_key** — the kernel keyring is shared with the host.
//!   * **acct / swapon / swapoff / reboot / syslog / quotactl** — machine-wide state.
//!
//! It is deliberately a denylist of the dangerous, not an allowlist of the permitted. An
//! allowlist is the stronger construction and it is also the one that breaks a build six
//! months from now when a toolchain starts using a syscall nobody predicted. The task this
//! filter has is to be a belt that never fires during honest work.
//!
//! `ptrace` is **not** denied. Debugging inside the sandbox is legitimate, and the
//! cross-process case — attaching to something outside the sandbox — is already refused by
//! Landlock, which confines `ptrace` to within a domain.
//!
//! # What it does not cover
//!
//! A non-native syscall ABI (a 32-bit binary on a 64-bit kernel) is **allowed through**
//! this filter. Denying it would break `-m32` builds, and it costs nothing that matters:
//! the mount policy and the Landlock domain are properties of the process, not of the ABI
//! it makes its calls through, so they hold for a 32-bit process exactly as they do for a
//! 64-bit one. Only this belt is native-ABI-only, and it says so.
//!
//! x32 on x86-64 is the one exception, and it is denied outright: x32 calls arrive under
//! the *same* `AUDIT_ARCH_X86_64` this filter matches, with `__X32_SYSCALL_BIT` set in the
//! number, so letting them through would be a bypass of the list above rather than a
//! different ABI honestly out of scope.

/// One classic-BPF instruction, `struct sock_filter`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;

/// Offsets into `struct seccomp_data`.
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;

pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// `SECCOMP_RET_ERRNO | EPERM`. `EPERM` prints as "Operation not permitted", which is one
/// of the three strings the Elixir side recognises as a sandbox denial — so if this belt
/// ever does fire, it fires legibly instead of looking like a mystery.
pub const SECCOMP_RET_EPERM: u32 = 0x0005_0000 | 1;

/// `__X32_SYSCALL_BIT`.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The `AUDIT_ARCH_*` constant for the architecture this binary was built for.
#[cfg(target_arch = "x86_64")]
pub const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
pub const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;
#[cfg(target_arch = "arm")]
pub const NATIVE_AUDIT_ARCH: u32 = 0x4000_0028;
#[cfg(target_arch = "x86")]
pub const NATIVE_AUDIT_ARCH: u32 = 0x4000_0003;
// Anything else: the filter is assembled and reported, but `install` refuses rather than
// guessing an architecture token, because a wrong one would match nothing and the filter
// would silently allow everything.
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86"
)))]
pub const NATIVE_AUDIT_ARCH: u32 = 0;

/// Whether this build knows its own `AUDIT_ARCH` token.
pub const ARCH_KNOWN: bool = NATIVE_AUDIT_ARCH != 0;

/// Assembles the filter for a denylist of syscall numbers.
///
/// Layout, and the jump arithmetic that goes with it:
///
/// ```text
///   0  LD   arch
///   1  JEQ  NATIVE_ARCH ? fallthrough : ALLOW      (a foreign ABI is out of scope)
///   2  LD   nr
///  [3] JGE  X32_SYSCALL_BIT ? DENY : fallthrough   (x86-64 only)
///   .  JEQ  denied[0] ? DENY : fallthrough
///   .  ...
///   A  RET  ALLOW
///  A+1 RET  ERRNO EPERM
/// ```
pub fn assemble(denied: &[u32], audit_arch: u32, guard_x32: bool) -> Vec<Instruction> {
    let prologue = if guard_x32 { 4 } else { 3 };
    // Index of the ALLOW instruction; DENY is the one after it.
    let allow_at = prologue + denied.len();
    let deny_at = allow_at + 1;

    let mut program = Vec::with_capacity(deny_at + 1);

    program.push(Instruction {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: OFFSET_ARCH,
    });
    program.push(Instruction {
        code: BPF_JMP_JEQ_K,
        jt: 0,
        // Not our ABI: jump to ALLOW. From index 1, that is `allow_at - 2` ahead.
        jf: offset(allow_at, 1),
        k: audit_arch,
    });
    program.push(Instruction {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: OFFSET_NR,
    });

    if guard_x32 {
        program.push(Instruction {
            code: BPF_JMP_JGE_K,
            jt: offset(deny_at, 3),
            jf: 0,
            k: X32_SYSCALL_BIT,
        });
    }

    for (i, nr) in denied.iter().enumerate() {
        let at = prologue + i;
        program.push(Instruction {
            code: BPF_JMP_JEQ_K,
            jt: offset(deny_at, at),
            jf: 0,
            k: *nr,
        });
    }

    program.push(Instruction {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });
    program.push(Instruction {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_EPERM,
    });

    program
}

/// A classic-BPF jump is "skip this many instructions after the next one", and the field
/// is a `u8`. The denylist is a few dozen entries, so the cast cannot truncate; the
/// assertion is here so that stops being true loudly rather than quietly if the list ever
/// grows past 255.
fn offset(target: usize, from: usize) -> u8 {
    let delta = target - from - 1;
    debug_assert!(
        delta <= u8::MAX as usize,
        "seccomp jump of {delta} does not fit in a u8; the denylist needs a jump table"
    );
    delta as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walks the assembled program the way the kernel does, so the jump arithmetic is
    /// checked against behaviour rather than against itself.
    fn evaluate(program: &[Instruction], arch: u32, nr: u32) -> u32 {
        let mut pc = 0usize;
        let mut acc = 0u32;
        let mut steps = 0;

        loop {
            steps += 1;
            assert!(steps < 1000, "program did not terminate");
            let instruction = program[pc];

            match instruction.code {
                BPF_LD_W_ABS => {
                    acc = match instruction.k {
                        OFFSET_NR => nr,
                        OFFSET_ARCH => arch,
                        other => panic!("unexpected load offset {other}"),
                    };
                    pc += 1;
                }
                BPF_JMP_JEQ_K => {
                    let taken = acc == instruction.k;
                    pc += 1 + if taken {
                        instruction.jt as usize
                    } else {
                        instruction.jf as usize
                    };
                }
                BPF_JMP_JGE_K => {
                    let taken = acc >= instruction.k;
                    pc += 1 + if taken {
                        instruction.jt as usize
                    } else {
                        instruction.jf as usize
                    };
                }
                BPF_RET_K => return instruction.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
        }
    }

    const ARCH: u32 = 0xc000_003e;
    const DENIED: &[u32] = &[165, 166, 155, 308];

    #[test]
    fn a_denied_syscall_on_the_native_arch_gets_eperm() {
        let program = assemble(DENIED, ARCH, true);
        for nr in DENIED {
            assert_eq!(evaluate(&program, ARCH, *nr), SECCOMP_RET_EPERM, "nr {nr}");
        }
    }

    #[test]
    fn an_ordinary_syscall_is_allowed() {
        let program = assemble(DENIED, ARCH, true);
        for nr in [0u32, 1, 2, 59, 257] {
            assert_eq!(evaluate(&program, ARCH, nr), SECCOMP_RET_ALLOW, "nr {nr}");
        }
    }

    #[test]
    fn a_foreign_abi_falls_through_to_allow() {
        // The documented limitation, pinned as behaviour so it cannot become accidental.
        let program = assemble(DENIED, ARCH, true);
        assert_eq!(
            evaluate(&program, 0x4000_0003, DENIED[0]),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn x32_is_denied_outright_because_it_shares_the_arch_token() {
        let program = assemble(DENIED, ARCH, true);
        // A syscall that would otherwise be allowed, made through x32.
        assert_eq!(
            evaluate(&program, ARCH, X32_SYSCALL_BIT | 1),
            SECCOMP_RET_EPERM
        );
    }

    #[test]
    fn without_the_x32_guard_the_program_is_one_shorter_and_still_correct() {
        let program = assemble(DENIED, ARCH, false);
        assert_eq!(program.len(), 3 + DENIED.len() + 2);
        assert_eq!(evaluate(&program, ARCH, DENIED[0]), SECCOMP_RET_EPERM);
        assert_eq!(evaluate(&program, ARCH, 1), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn an_empty_denylist_allows_everything_rather_than_falling_off_the_end() {
        let program = assemble(&[], ARCH, false);
        assert_eq!(evaluate(&program, ARCH, 1), SECCOMP_RET_ALLOW);
        assert_eq!(evaluate(&program, 0x1234, 1), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn the_jump_offsets_stay_inside_a_u8_for_a_realistic_denylist() {
        let denied: Vec<u32> = (0..200).collect();
        let program = assemble(&denied, ARCH, true);
        assert_eq!(evaluate(&program, ARCH, 199), SECCOMP_RET_EPERM);
        assert_eq!(evaluate(&program, ARCH, 1000), SECCOMP_RET_ALLOW);
    }
}
