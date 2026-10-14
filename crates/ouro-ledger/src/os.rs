//! Process facts shared by every ownership and peer check.

/// The effective uid every private file, directory and peer must match.
pub(crate) fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments, reads no caller memory and cannot fail.
    unsafe { libc::geteuid() }
}
