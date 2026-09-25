//! `ouro-jail`: run an operator-supplied argv under an explicit policy and
//! record what was applied, what was observed and what remains unknown.
//!
//! The module layout follows jail-v1 §4. Portable code owns CLI parsing,
//! configuration provenance, policy narrowing, profile expansion, capability
//! requirements, lifecycle transitions, redaction, record encoding and resource
//! budgets; [`platform`] owns everything native.

/// Write one diagnostic line to standard error, ignoring a failed write.
///
/// `eprintln!` panics when the write fails, which replaces the exit code the
/// caller is about to return (§6.4) with a panic's 101. Standard error is
/// whatever the operator passed, including a descriptor that rejects writes
/// (an io_uring, which the run then refuses): a diagnostic that cannot be
/// written is dropped, and the exit code stands.
pub fn diagnostic(args: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_fmt(args);
    let _ = stderr.write_all(b"\n");
}

/// [`diagnostic`] with `format!` syntax: a non-panicking `eprintln!`.
#[macro_export]
macro_rules! diag {
    ($($arg:tt)*) => {
        $crate::diagnostic(format_args!($($arg)*))
    };
}

pub mod canonical;
pub mod capability;
pub mod cleanup;
pub mod cli;
pub mod config;
// J3-launch begin: credential staging
pub mod credentials;
// J3-launch end
// J3-none begin: reserved environment names (§12)
pub mod environment;
// J3-none end
// J4-G begin: `gc` reconciliation (§14.2, C03)
pub mod gc;
// J4-G end
// J3-launch begin: data-only launch profiles
pub mod launch_profile;
// J3-launch end
pub mod network;
pub mod observer;
pub mod platform;
pub mod policy;
pub mod profiles;
// J3-P begin: the outside HTTP proxy library (jail-v1 §10)
pub mod proxy;
// J3-P end
pub mod records;
pub mod state;
pub mod supervisor;
pub mod trace;
