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

/// Nanoseconds since this supervisor started, on the §6.4 continuous clock.
///
/// jail-v1 §13.1 fixes one base for every `monotonic_ns` in the trace, from
/// every source: on Linux it is `CLOCK_BOOTTIME` at supervisor start, so
/// suspend counts and wall-clock adjustments do not move it. Platforms that
/// only refuse execution label their refusal-path notes with a monotonic
/// fallback; no execution claim rides on it.
#[must_use]
pub fn elapsed_since_start_ns() -> u128 {
    #[cfg(target_os = "linux")]
    {
        u128::from(linux::clock::supervisor_elapsed_ns())
    }
    #[cfg(not(target_os = "linux"))]
    {
        FALLBACK_START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_nanos()
    }
}

/// Record the supervisor's start on the continuous clock.
///
/// Called once at the top of `run`; later calls are harmless because the
/// first value wins.
pub fn mark_supervisor_start() {
    #[cfg(target_os = "linux")]
    {
        let _ = linux::clock::mark_supervisor_start();
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = FALLBACK_START.get_or_init(std::time::Instant::now);
    }
}

#[cfg(not(target_os = "linux"))]
static FALLBACK_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

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
    // J3-launch begin: vendor state and bind_ro handles staged by the
    // supervisor, bound by descriptor (§9.1, §12). A field, so the platform
    // receives the exact objects staging examined instead of re-resolving
    // paths. (The other J3-launch change here is the additive
    // `release_reporting_teardown` default method.)
    /// The vendor-state directory and `bind_ro` sources, when a launch
    /// profile needs them; `None` otherwise.
    pub launch: Option<crate::credentials::LaunchHandoff>,
    // J3-launch end
    // J3-agent begin: the registered proxy directory (jail-v1 §10)
    /// The attempt's registered, 0700 proxy directory, for a proxy-mode
    /// profile; `None` otherwise. The platform binds the proxy socket inside
    /// it and exposes it read-only by this descriptor.
    pub proxy: Option<ProxyDirHandoff>,
    // J3-agent end
}

// J3-agent begin: the proxy directory hand-off
/// The proxy directory the supervisor registered and created (§10).
#[derive(Clone)]
pub struct ProxyDirHandoff {
    /// `<attempt>/proxy`, for diagnostics; never bound or resolved by path.
    pub host_path: PathBuf,
    /// The directory, opened by the supervisor at creation.
    pub fd: std::sync::Arc<std::os::fd::OwnedFd>,
    /// Its `(dev, ino)` as registered in jail state.
    pub identity: (u64, u64),
}

impl PartialEq for ProxyDirHandoff {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity && self.host_path == other.host_path
    }
}

impl Eq for ProxyDirHandoff {}

impl std::fmt::Debug for ProxyDirHandoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyDirHandoff")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
// J3-agent end

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
    /// The enforcement backend's name, for the receipt's `jail.backend`.
    ///
    /// ADDITIVE, defaulting to `None`: `jail.backend` and `backend_version`
    /// are facts about the mechanism that made the boundary, which only the
    /// platform that made it knows. `applied` is reported separately through
    /// [`PreparedExecution::applied`].
    pub backend: Option<String>,
    /// The backend's own version string, as the backend reports it.
    pub backend_version: Option<String>,
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
    /// A bounded polling step completed; recheck signals and transport health.
    Poll,
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

/// The supervisor's own birth identity, for the state file (§7): the pid
/// plus the boot id and start-time ticks that make it unambiguous across
/// pid reuse and reboots.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OwnerIdentity {
    /// The supervisor's process id.
    pub pid: u32,
    /// `/proc/sys/kernel/random/boot_id`.
    pub boot_id: String,
    /// The supervisor's field 22 of `/proc/<pid>/stat`.
    pub start_time_ticks: u64,
}

/// The platform contract (§4).
pub trait Platform {
    /// Who this binary is running as.
    fn identity(&self) -> PlatformIdentity;

    /// The supervisor's birth identity, where the platform can establish one
    /// (§7). `None` on platforms that only refuse execution.
    fn owner_identity(&self) -> Option<OwnerIdentity> {
        None
    }

    /// Measures the capabilities the plan needs; a run asks for nothing else.
    fn probe(&self, plan: &PlanRequest) -> Vec<Capability>;

    /// Measures every capability this platform can probe, for `doctor`, which
    /// reports the host and not only the plan (§14.1). A platform whose probe
    /// set is exactly the plan's leaves the default.
    fn probe_all(&self, plan: &PlanRequest) -> Vec<Capability> {
        self.probe(plan)
    }

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

    // J3-launch begin: a failed release reports its teardown (§13.2 row 4)
    /// [`PreparedExecution::release`], plus what the teardown after a failed
    /// release established about the tree.
    ///
    /// ADDITIVE, with a default that reports nothing (`None`), which the
    /// supervisor records as an unverified tree: exactly today's behaviour.
    /// A platform that tears the boundary down on a failed release and can
    /// verify that teardown overrides it, so the refused receipt can say
    /// `tree_empty = true` and vendor state can be removed honestly.
    ///
    /// # Errors
    /// The release refusal and, when one ran, the teardown's observation.
    fn release_reporting_teardown(
        self: Box<Self>,
    ) -> Result<Box<dyn RunningExecution>, Box<ReleaseFailure>> {
        self.release().map_err(|error| {
            Box::new(ReleaseFailure {
                error,
                teardown: None,
            })
        })
    }
    // J3-launch end
}

// J3-launch begin: a failed release with its teardown
/// Why a release failed, and what the teardown it ran established.
#[derive(Debug)]
pub struct ReleaseFailure {
    /// The refusal.
    pub error: JailError,
    /// The teardown's observation, when the platform ran and can report one.
    pub teardown: Option<Teardown>,
}
// J3-launch end

/// A released execution (§4).
pub trait RunningExecution {
    /// Final kernel-measured tree ceilings, including counter-based hits.
    fn final_limits(&self) -> Vec<crate::records::AppliedLimit> {
        Vec::new()
    }

    /// A resource event that actually caused termination, never inferred from
    /// an exit code or from ordinary CPU bandwidth throttling.
    fn limit_cause(&self) -> Option<String> {
        None
    }
    // J3-none begin: a detected lifetime-integrity loss reaches the next receipt (§9.3)
    /// Whether the platform has detected, while running, that the boundary's
    /// lifetime integrity was lost: a membership escape, a replaced identity
    /// or a failed verification. Once true it stays true. The default is a
    /// platform that detects no such loss before tree verification.
    fn integrity_lost(&self) -> bool {
        false
    }
    // J3-none end

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
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::platform::LinuxPlatform::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
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
