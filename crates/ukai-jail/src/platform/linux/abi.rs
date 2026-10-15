//! Native Linux syscall ABI. Portable builds render the x86_64 reference
//! tables; Linux aarch64 builds select the asm-generic 64-bit table. Unknown
//! architectures remain refused by capability preflight.
//!
//! Numbers: Linux arch/x86/entry/syscalls/syscall_64.tbl and
//! include/uapi/asm-generic/unistd.h. Native tests cross-check against libc.

/// Whether this build emits the aarch64 Linux tables.
pub const AARCH64: bool = cfg!(all(target_os = "linux", target_arch = "aarch64"));
pub const TABLE_ARCH: &str = if AARCH64 { "aarch64" } else { "x86_64" };

/// `AUDIT_ARCH_X86_64` (`include/uapi/linux/audit.h`): `EM_X86_64` with the
/// 64-bit and little-endian flags. The x32 ABI reports this arch too, and is
/// told apart by the x32 bit in the syscall number.
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// `AUDIT_ARCH_AARCH64`: `EM_AARCH64` with the 64-bit and little-endian flags.
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
/// `AUDIT_ARCH_I386`: `int 0x80` entries on an x86_64 kernel carry this arch
/// and numbers from the i386 table.
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003;
/// `AUDIT_ARCH_ARM`: 32-bit (compat) entries on an arm64 kernel.
pub const AUDIT_ARCH_ARM: u32 = 0x4000_0028;

/// The audit architecture of this build's native syscall table.
pub const AUDIT_ARCH: u32 = if AARCH64 {
    AUDIT_ARCH_AARCH64
} else {
    AUDIT_ARCH_X86_64
};

/// Select a number from the explicitly paired native syscall tables.
pub const fn nr(x86_64: u32, aarch64: u32) -> u32 {
    if AARCH64 { aarch64 } else { x86_64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audit architectures are the kernel's: `EM_*` machine numbers
    /// with `__AUDIT_ARCH_64BIT` (0x8000_0000) and `__AUDIT_ARCH_LE`
    /// (0x4000_0000) as `include/uapi/linux/audit.h` composes them.
    #[test]
    fn audit_architectures_compose_as_the_kernel_does() {
        const BIT64: u32 = 0x8000_0000;
        const LE: u32 = 0x4000_0000;
        const EM_386: u32 = 3;
        const EM_ARM: u32 = 40;
        const EM_X86_64: u32 = 62;
        const EM_AARCH64: u32 = 183;
        assert_eq!(AUDIT_ARCH_X86_64, EM_X86_64 | BIT64 | LE);
        assert_eq!(AUDIT_ARCH_AARCH64, EM_AARCH64 | BIT64 | LE);
        assert_eq!(AUDIT_ARCH_I386, EM_386 | LE);
        assert_eq!(AUDIT_ARCH_ARM, EM_ARM | LE);
        assert_eq!(
            AUDIT_ARCH,
            if AARCH64 {
                AUDIT_ARCH_AARCH64
            } else {
                AUDIT_ARCH_X86_64
            }
        );
    }
}
