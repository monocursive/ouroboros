//! Native Linux syscall ABI. Portable builds render the x86_64 reference
//! tables; Linux aarch64 builds select the asm-generic 64-bit table. Unknown
//! architectures remain refused by capability preflight.
//!
//! Numbers: Linux arch/x86/entry/syscalls/syscall_64.tbl and
//! include/uapi/asm-generic/unistd.h. Native tests cross-check against libc.

/// Whether this build emits the aarch64 Linux tables.
pub const AARCH64: bool = cfg!(all(target_os = "linux", target_arch = "aarch64"));
pub const TABLE_ARCH: &str = if AARCH64 { "aarch64" } else { "x86_64" };
pub const AUDIT_ARCH: u32 = if AARCH64 { 0xc000_00b7 } else { 0xc000_003e };

/// Select a number from the explicitly paired native syscall tables.
pub const fn nr(x86_64: u32, aarch64: u32) -> u32 {
    if AARCH64 { aarch64 } else { x86_64 }
}
