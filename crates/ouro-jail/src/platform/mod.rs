//! The platform seam.
//!
//! Implements the conceptual interfaces of jail-v1 §4 and the support matrix of
//! §3.2. Shared code owns policy, records, lifecycle transitions and budgets;
//! platform code owns launch mechanics, containment, observation, process
//! identity, tree termination and durability primitives.
//!
//! A [`PreparedExecution`] owns an actual blocked launcher and actual applied
//! resources, and exposes the child boundary's identity before release. A
//! platform that cannot do something returns a typed unsupported result; it
//! never returns a successful no-op (§4).

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use crate::capability::Capability;
use crate::policy::{PolicySnapshot, ProfileName};
use crate::records::{JailError, NativeLifetime, Os, ProcessRecord};
use crate::trace::SharedTrace;

pub mod macos;

// `linux` is declared unconditionally: its `bpf` and `seccomp` modules describe
// a Linux ABI without calling into it, so they build and test on every host;
// everything that touches Linux is gated inside `platform/linux/mod.rs`.
pub mod linux;

/// Who this binary is running as, for the receipt's `platform` group.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlatformIdentity {
    /// `linux` or `macos`.
    pub os: Os,
    /// The architecture this binary was built for.
    pub arch: String,
    /// The kernel release string, or a stated unknown.
    pub kernel: String,
}

/// What the supervisor asks a platform to plan for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlanRequest {
    /// The resolved policy.
    pub snapshot: PolicySnapshot,
    /// The base profile.
    pub profile: ProfileName,
    /// The capability requirements the policy derives.
    pub requirements: Vec<String>,
}

/// Everything a platform needs to build the boundary and the blocked launcher.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreparedPlan {
    /// The attempt identifier.
    pub attempt_id: String,
    /// The attempt directory this attempt owns.
    pub attempt_dir: PathBuf,
    /// The planning request.
    pub request: PlanRequest,
    /// The literal operator argv, including `PROGRAM`.
    pub argv: Vec<Vec<u8>>,
    /// The absolute resolved workspace.
    pub workspace: PathBuf,
}

/// The output channels a prepared execution may write to.
///
/// The child inherits none of these (§6.1); they belong to the supervisor and
/// to the observer that lives beside it.
pub struct Sinks {
    /// The bounded trace sink, when one was prepared. Shared with the
    /// supervisor, which writes its own wrapper events to the same stream.
    pub trace: Option<SharedTrace>,
}

impl std::fmt::Debug for Sinks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sinks")
            .field("trace", &self.trace.is_some())
            .finish()
    }
}

/// The identity of the boundary a prepared execution created (§4).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BoundaryIdentity {
    /// `pid_namespace`, `supervisor_cgroup` or `native_tree`.
    pub boundary: String,
    /// The scope tree verification will claim: `attempt_tree` or
    /// `registered_boundary`.
    pub verification_scope: String,
    /// OS-tagged native identities.
    pub native: Option<NativeLifetime>,
    /// The blocked launcher's stable identity.
    pub process: Option<ProcessRecord>,
}

/// Why the supervisor is asking for termination (§9.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StopReason {
    /// The supervisor received INT, TERM or HUP.
    OperatorSignal,
    /// The wall deadline expired.
    WallExpiry,
    /// Evidence was lost under strict mode.
    EvidenceLoss,
    /// The target exited and descendants remain.
    TargetExit,
}

/// One thing that happened while the target was running.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RunEvent {
    /// The target `exec` transition was confirmed; the enforced receipt and
    /// the `exec_confirmed` control message follow from it.
    ExecConfirmed,
    /// The target exited with this code.
    TargetExited {
        /// The exit code.
        code: u8,
    },
    /// The target was terminated by this signal.
    TargetSignaled {
        /// The signal number.
        signal: u32,
    },
    /// The target `exec` itself failed.
    ExecError {
        /// The errno name the launcher reported.
        errno: String,
    },
    /// The wall deadline expired.
    WallExpired,
    /// Evidence was lost.
    EvidenceLost {
        /// A safe reason.
        reason: String,
    },
    /// The facts needed are missing; never a fabricated outcome.
    Unknown {
        /// A safe reason.
        reason: String,
    },
}

/// A monotonic deadline (§6.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Deadline {
    /// When the budget expires, or `None` when the caller is only draining.
    pub at: Option<Instant>,
}

/// What tree verification established (§9.3, §13.2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TreeObservation {
    /// True only after verified emptiness; `None` when it could not be
    /// established within the budget.
    pub tree_empty: Option<bool>,
    /// When verification completed, only with a non-null `tree_empty`.
    pub verified_at: Option<SystemTime>,
    /// `attempt_tree` or `registered_boundary`.
    pub verification_scope: String,
    /// `pending`, `verified` or `lost`.
    pub integrity: String,
}

/// What an aborted preparation left behind.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Teardown {
    /// The tree facts after teardown, when any boundary existed.
    pub tree: Option<TreeObservation>,
}

/// The platform contract (§4).
pub trait Platform {
    /// Who this binary is running as.
    fn identity(&self) -> PlatformIdentity;

    /// Measures the capabilities the plan needs. `doctor` and `run` share it.
    fn probe(&self, plan: &PlanRequest) -> Vec<Capability>;

    /// Creates the boundary and the blocked launcher.
    ///
    /// # Errors
    /// Returns a typed refusal when the platform cannot create them. It never
    /// returns a successful no-op.
    fn prepare(
        &self,
        plan: PreparedPlan,
        sinks: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError>;
}

/// A boundary that exists, with the target still blocked (§4).
pub trait PreparedExecution {
    /// The boundary's identity, available before release.
    fn boundary(&self) -> BoundaryIdentity;

    /// What this boundary actually applied, for the receipt's `applied` group.
    ///
    /// ADDITIVE, with a default of `None`: a platform that reports nothing
    /// leaves the supervisor's own view in place, which today is the wall
    /// ceiling the supervisor itself enforces. The Linux slice overrides it
    /// when it wires the mechanisms into this trait, because §13.2 wants
    /// "actually applied filesystem/network/syscall mechanisms and limit
    /// scopes" and only the platform knows them.
    fn applied(&self) -> Option<crate::records::Applied> {
        None
    }

    /// Releases the blocked launcher so it execs the target.
    ///
    /// # Errors
    /// Returns a typed refusal when the release fails.
    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, JailError>;

    /// Tears the prepared resources down without ever running the target.
    ///
    /// # Errors
    /// Returns a typed error when teardown could not be completed or verified.
    fn abort(self: Box<Self>) -> Result<Teardown, JailError>;
}

/// A released execution (§4).
pub trait RunningExecution {
    /// Waits for the next event, up to `deadline`.
    fn wait(&mut self, deadline: Deadline) -> RunEvent;

    /// Asks for termination; the caller owns the lifecycle transition.
    fn request_stop(&mut self, reason: StopReason);

    /// Verifies tree death within `budget`.
    fn wait_tree(&mut self, budget: Duration) -> TreeObservation;

    /// Drains the observer and returns its summary, when one ran.
    fn observer_summary(&mut self) -> Option<crate::observer::CoverageSummary>;
}

/// The kernel release string, or a stated unknown.
///
/// `uname` is the direct fact. When it fails, the string says so rather than
/// guessing a version.
#[must_use]
pub fn kernel_release() -> String {
    let mut buffer = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: `uname` fills the caller-provided `utsname` and returns 0 on
    // success. The buffer is correctly sized and aligned for that struct, and
    // it is only read after a successful return.
    let result = unsafe { libc::uname(buffer.as_mut_ptr()) };
    if result != 0 {
        return "unknown".to_owned();
    }
    // SAFETY: `uname` returned 0, so every field of the struct is initialized.
    let filled = unsafe { buffer.assume_init() };
    let field = |bytes: &[libc::c_char]| -> String {
        // SAFETY: on a successful `uname` every field is a NUL-terminated C
        // string inside its own fixed-size array, so reading from the array's
        // first element stops at that NUL.
        let text = unsafe { std::ffi::CStr::from_ptr(bytes.as_ptr()) };
        text.to_string_lossy().into_owned()
    };
    let system = field(&filled.sysname);
    let release = field(&filled.release);
    if system.is_empty() && release.is_empty() {
        return "unknown".to_owned();
    }
    format!("{system} {release}").trim().to_owned()
}

/// The platform this build targets.
#[must_use]
pub fn current() -> Box<dyn Platform> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacosPlatform)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(Unimplemented)
    }
}

/// The placeholder platform for targets whose slice is not in this build.
///
/// It refuses with `backend_unavailable` rather than pretending to run
/// anything. On Linux the execution slice replaces it; until then a Linux build
/// compiles and refuses honestly instead of silently doing nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Unimplemented;

impl Platform for Unimplemented {
    fn identity(&self) -> PlatformIdentity {
        PlatformIdentity {
            os: if cfg!(target_os = "linux") {
                Os::Linux
            } else {
                Os::Macos
            },
            arch: std::env::consts::ARCH.to_owned(),
            kernel: kernel_release(),
        }
    }

    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        plan.requirements
            .iter()
            .map(|name| {
                Capability::unsupported(
                    name.clone(),
                    crate::capability::CapabilityScope::Tree,
                    "platform_slice_absent",
                )
            })
            .collect()
    }

    fn prepare(
        &self,
        _plan: PreparedPlan,
        _sinks: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        Err(JailError::new(
            crate::records::ErrorCode::BackendUnavailable,
            crate::records::ErrorStage::Probing,
            crate::records::Remediation::Unsupported,
            "this build does not contain an execution slice for the running platform".to_owned(),
        ))
    }
}
