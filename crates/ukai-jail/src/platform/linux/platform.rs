//! The Linux platform: probing, preparation, release, lifetime.
//!
//! This is the seam of jail-v1 §4 filled in with the mechanisms of §9. The
//! supervisor owns every lifecycle transition and every receipt; the
//! platform owns the boundary, the blocked launcher, the observer's
//! attachment and the verification of tree death, and it reports back only
//! what it read from the kernel. This file is the entry point and the fixed
//! descriptor layout; the parts live beside it: `requirements` (probes to
//! capabilities), `mounts` (the mount plan), `stdio` (the relays),
//! `boundary` (preparation, release, teardown), `running` (the run loop)
//! and `verdict` (what the end of a run justifies).
//!
//! The process tree is supervisor → `bwrap` → namespace init → inside
//! launcher → target. The launcher is this same binary, bound read-only at
//! `/run/ukai/jail` and re-executed with the hidden `__launch` subcommand, so
//! nothing but the target's own code runs after the boundary is closed.
//! An outside watcher is a sibling of bubblewrap; its pidfds close the backend's
//! startup parent-death window. A resource leaf includes bubblewrap, namespace
//! init and the target tree, while the supervisor/observer/watcher stay outside.

use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::capability::{Capability, Requirement};
use crate::platform::{
    PlanRequest, Platform, PlatformIdentity, PreparedExecution, PreparedPlan, Sinks, kernel_release,
};
use crate::policy::ProfileName;
use crate::records::{ErrorCode, ErrorStage, JailError, Os, Remediation, rfc3339_utc};

use super::boundary::prepare_timeout;
use super::bwrap;
use super::clock;
use super::fs as jfs;
use super::identity;
use super::probe;
use super::requirements::{derive, probes_for};

pub(crate) use super::mounts::refuse_pseudo_fs_grants;
pub(crate) use super::mounts::{PlanPaths, plan_for};

// The fixed descriptor numbers of the backend's map and the launcher's,
// by the names the platform uses; [`super::fds`] is the table that holds
// them and checks them.

/// Where the attempt's narrowing `SECCOMP_RET_DATA` reaches the launcher.
pub(super) const TRACE_DATA_FD: RawFd = super::fds::TRACE_DATA;
/// Descriptor the seccomp program is handed to bubblewrap on.
pub(crate) const SECCOMP_FD: RawFd = super::fds::SECCOMP;
/// Descriptor bubblewrap writes its JSON status to.
pub(crate) const STATUS_FD: RawFd = super::fds::STATUS;
/// Descriptor the launcher blocks reading (`__launch --release-fd`), and the
/// one a gate checks it is blocked on.
pub(super) const RELEASE_FD: RawFd = super::fds::RELEASE;
/// Descriptor the launcher writes a failed exec's errno to
/// (`__launch --error-fd`).
pub(super) const ERROR_FD: RawFd = super::fds::ERROR;
/// Descriptor a long argument list is handed over.
pub(crate) const ARGS_FD: RawFd = super::fds::ARGS;
/// Descriptor the vendor-state directory is handed to bubblewrap on.
pub(crate) const VENDOR_STATE_FD: RawFd = super::fds::VENDOR_STATE;
/// First descriptor of the pinned binds.
pub(super) const PINNED_FD_BASE: RawFd = super::fds::PINNED_BASE;

/// The Linux platform.
#[derive(Clone, Debug)]
pub struct LinuxPlatform {
    /// The resolved backend, or why none was.
    bwrap: Result<PathBuf, String>,
    backend_pin: Result<std::sync::Arc<jfs::PinnedPath>, String>,
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxPlatform {
    /// The platform with the bubblewrap this process resolved once from the
    /// operator's `PATH` ([`resolved_bwrap`]).
    #[must_use]
    pub fn new() -> Self {
        // Read before anything this process does raises it.
        let _ = super::exec::operator_nofile_soft();
        let backend_pin = resolved_bwrap().map_err(str::to_owned).and_then(|path| {
            jfs::PinnedPath::open(path)
                .map(std::sync::Arc::new)
                .map_err(|e| e.to_string())
        });
        LinuxPlatform {
            backend_pin,
            bwrap: resolved_bwrap()
                .map(Path::to_path_buf)
                .map_err(str::to_owned),
        }
    }

    /// The backend as the probes take it: the path, or why there is none.
    fn backend(&self) -> Result<&Path, &str> {
        self.bwrap.as_deref().map_err(String::as_str)
    }
}

// Bubblewrap, resolved once (review F1, F2)
/// The backend, resolved from a `PATH` value.
///
/// The first *absolute* entry that holds an executable regular file named
/// `bwrap`, canonicalized, so the path recorded is the file that runs. An
/// empty entry (which a shell-style lookup reads as the current directory)
/// and a relative entry are skipped: either would let the working directory
/// pick the backend. There is no fallback to a well-known location, and an
/// unset `PATH` is not replaced by the C library's default search path: an
/// operator whose `PATH` does not name bubblewrap has not provisioned it,
/// and `doctor` says the backend is unavailable rather than reach past what
/// they configured (§3.2).
///
/// # Errors
/// Why no backend was found, for the `bwrap_present` evidence.
pub fn resolve_bwrap(path: Option<&std::ffi::OsStr>) -> Result<PathBuf, String> {
    let Some(path) = path else {
        return Err("PATH is unset, so no bubblewrap is provisioned for this process".to_owned());
    };
    let mut skipped = Vec::new();
    for dir in std::env::split_paths(path) {
        if dir.as_os_str().is_empty() || !dir.is_absolute() {
            skipped.push(format!("{:?}", dir.display().to_string()));
            continue;
        }
        let Ok(canonical) = std::fs::canonicalize(dir.join("bwrap")) else {
            continue;
        };
        let Ok(meta) = std::fs::metadata(&canonical) else {
            continue;
        };
        let Ok(c_path) = std::ffi::CString::new(canonical.as_os_str().as_bytes()) else {
            continue;
        };
        // SAFETY: `c_path` is a live NUL-terminated string; access reads it.
        let executable = unsafe { libc::access(c_path.as_ptr(), libc::X_OK) } == 0;
        if meta.is_file() && executable {
            return Ok(canonical);
        }
    }
    let mut reason = "no executable `bwrap` in any absolute PATH entry".to_owned();
    if !skipped.is_empty() {
        reason.push_str(&format!(
            " (empty or relative entries are never searched: {})",
            skipped.join(", ")
        ));
    }
    Err(reason)
}

/// [`resolve_bwrap`] of this process's `PATH`, computed once: every probe,
/// every run and `doctor`'s record use this one path.
///
/// # Errors
/// Why no backend was found.
pub fn resolved_bwrap() -> Result<&'static Path, &'static str> {
    static RESOLVED: std::sync::OnceLock<Result<PathBuf, String>> = std::sync::OnceLock::new();
    RESOLVED
        .get_or_init(|| resolve_bwrap(std::env::var_os("PATH").as_deref()))
        .as_deref()
        .map_err(String::as_str)
}

/// Whether the resolved bubblewrap is new enough for the rendered argv
/// (`--bind-fd` and `--ro-bind-fd` arrived in 0.10.0): `Ok(())`, or a refusal
/// naming the version it reports and the floor it misses.
///
/// Asked once per process, within the preparation budget it runs in (§8.2)
/// and at most a probe's deadline. The answer is kept; a question the budget
/// ended is not an answer, so it refuses as the budget's timeout and is asked
/// again next time.
fn bwrap_meets_minimum(deadline: clock::Deadline) -> Result<(), JailError> {
    static ANSWER: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    let refusal = |reason: &String| {
        error(
            ErrorCode::BackendUnavailable,
            ErrorStage::Preparing,
            Remediation::HostSetup,
            reason.clone(),
        )
    };
    if let Some(answer) = ANSWER.get() {
        return answer.as_ref().map_err(refusal).copied();
    }
    let bwrap = resolved_bwrap().map_err(|reason| refusal(&reason.to_owned()))?;
    let answer = ask_minimum(bwrap, deadline)?;
    ANSWER
        .get_or_init(|| answer)
        .as_ref()
        .map_err(refusal)
        .copied()
}

/// [`bwrap_meets_minimum`]'s answer for `bwrap`, asked within `deadline`
/// and at most a probe's deadline.
///
/// # Errors
/// The budget's timeout when `deadline` ended the question: that is no
/// answer about the backend.
fn ask_minimum(bwrap: &Path, deadline: clock::Deadline) -> Result<Result<(), String>, JailError> {
    let asked = clock::Deadline::after(probe::PROBE_DEADLINE.min(deadline.remaining()));
    match bwrap::bwrap_version(bwrap, asked) {
        Ok(version) if version.at_least(bwrap::MINIMUM_VERSION) => Ok(Ok(())),
        Ok(version) => Ok(Err(format!(
            "the resolved bubblewrap ({}) reports {}; every contained run renders \
             --bind-fd/--ro-bind-fd, which need bubblewrap >= 0.10.0",
            bwrap.display(),
            version.raw
        ))),
        Err(e) if deadline.expired() => Err(prepare_timeout(&format!(
            "preparation did not complete within its budget: {e}"
        ))),
        Err(e) => Ok(Err(format!(
            "the resolved bubblewrap ({}) could not be asked for its version: {e}",
            bwrap.display()
        ))),
    }
}

pub(super) fn error(
    code: ErrorCode,
    stage: ErrorStage,
    remediation: Remediation,
    message: String,
) -> JailError {
    JailError::new(code, stage, remediation, message)
}

pub(super) fn preparing(code: ErrorCode, message: impl Into<String>) -> JailError {
    error(
        code,
        ErrorStage::Preparing,
        Remediation::HostSetup,
        message.into(),
    )
}

impl LinuxPlatform {
    /// Runs the probes `wanted` selects, in report order, and derives the
    /// plan's capabilities from them.
    fn measure(&self, plan: &PlanRequest, wanted: impl Fn(&str) -> bool) -> Vec<Capability> {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe"));
        let names: Vec<&str> = probe::PROBE_NAMES
            .iter()
            .filter(|name| wanted(name))
            .copied()
            .collect();
        let results = probe::run_selected(&names, &exe, self.backend());
        derive(plan, &results, &rfc3339_utc(SystemTime::now()))
    }
}

impl Platform for LinuxPlatform {
    fn owner_identity(&self) -> Option<crate::platform::OwnerIdentity> {
        let identity = identity::ProcessIdentity::own().ok()?;
        Some(crate::platform::OwnerIdentity {
            pid: identity.pid as u32,
            boot_id: identity.boot_id,
            start_time_ticks: identity.start_time_ticks,
        })
    }
    fn identity(&self) -> PlatformIdentity {
        PlatformIdentity {
            os: Os::Linux,
            arch: std::env::consts::ARCH.to_owned(),
            kernel: kernel_release(),
        }
    }

    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        // A run measures what its plan asks about: every probe is a real
        // sandbox, fork or ptrace session, and the leaf and observer probes
        // are not free. `doctor` runs them all through `probe_all`.
        // `none` terminates its tree through the delegated leaf (§9.3)
        // Shadows the fn for this call only; the closure falls back to it.
        let probes_for = |requirement: Requirement| {
            super::uncontained::probes_for(plan.snapshot.profile, requirement)
                .unwrap_or_else(|| probes_for(requirement))
        };
        let wanted: std::collections::BTreeSet<&str> = plan
            .requirements
            .iter()
            .flat_map(|requirement| probes_for(*requirement).iter().copied())
            .collect();
        self.measure(plan, |name| wanted.contains(name))
    }

    fn probe_all(&self, plan: &PlanRequest) -> Vec<Capability> {
        self.measure(plan, |_| true)
    }

    fn prepare(
        &self,
        plan: PreparedPlan,
        sinks: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        // §8.2: what the supervisor's preparation budget has left, on the
        // same boot clock. A budget already spent refuses before anything
        // is built, rather than at the first wait that notices it.
        let deadline = clock::Deadline::after(plan.prepare_deadline.remaining());
        if deadline.expired() {
            return Err(prepare_timeout(
                "preparation did not complete within its budget: it was spent before the \
                 boundary was built",
            ));
        }
        // The uncontained profile has its own registered boundary (§9.3)
        if plan.request.snapshot.profile == ProfileName::None {
            return super::uncontained::prepare(plan, sinks, deadline);
        }
        // Never a bare name, so nothing but the resolved file runs.
        let bwrap = self.backend().map_err(|reason| {
            error(
                ErrorCode::BackendUnavailable,
                ErrorStage::Preparing,
                Remediation::HostSetup,
                format!("bubblewrap is not available: {reason}"),
            )
        })?;
        // A backend too old for the rendered argv refuses here with the
        // version it reports, instead of exiting 125 during setup behind an
        // empty diagnostic.
        bwrap_meets_minimum(deadline)?;
        let pin = self
            .backend_pin
            .as_ref()
            .map_err(|e| preparing(ErrorCode::BackendUnavailable, e.clone()))?;
        Ok(Box::new(super::boundary::create(
            bwrap, pin, plan, sinks, deadline,
        )?))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::time::Duration;

    // Bubblewrap resolution (review F1, F2)
    fn executable(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn bubblewrap_resolves_only_from_absolute_entries_to_a_canonical_file() {
        use std::ffi::OsStr;
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let first = root.join("first");
        let second = root.join("second");
        let link = root.join("link");
        for d in [&first, &second, &link] {
            std::fs::create_dir(d).unwrap();
        }
        executable(&second.join("bwrap"));
        let second_s = second.to_str().unwrap().to_owned();

        // An empty, a `.` and a relative entry are never searched, even
        // listed first; the first absolute entry holding one wins.
        for path in [
            format!(":{second_s}"),
            format!(".:{second_s}"),
            format!("rel:{second_s}"),
            format!("{}:{second_s}", first.display()),
        ] {
            assert_eq!(
                super::resolve_bwrap(Some(OsStr::new(&path))).unwrap(),
                second.join("bwrap"),
                "{path}"
            );
        }
        // A symlink is recorded as the file it names.
        std::os::unix::fs::symlink(second.join("bwrap"), link.join("bwrap")).unwrap();
        assert_eq!(
            super::resolve_bwrap(Some(OsStr::new(link.to_str().unwrap()))).unwrap(),
            second.join("bwrap")
        );
        // Not executable, or not a regular file: skipped.
        std::fs::write(first.join("bwrap"), b"").unwrap();
        std::fs::set_permissions(first.join("bwrap"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        std::fs::create_dir(root.join("dir-named")).unwrap();
        std::fs::create_dir(root.join("dir-named").join("bwrap")).unwrap();
        let path = format!(
            "{}:{}:{second_s}",
            first.display(),
            root.join("dir-named").display()
        );
        assert_eq!(
            super::resolve_bwrap(Some(OsStr::new(&path))).unwrap(),
            second.join("bwrap")
        );
        // Nothing absolute holds one: refused, with the reason.
        for path in ["", ":", ".", "rel:.:"] {
            let reason = super::resolve_bwrap(Some(OsStr::new(path))).unwrap_err();
            assert!(reason.contains("no executable `bwrap`"), "{path}: {reason}");
            assert!(reason.contains("never searched"), "{path}: {reason}");
        }
        let reason = super::resolve_bwrap(Some(OsStr::new(first.to_str().unwrap()))).unwrap_err();
        assert!(!reason.contains("never searched"), "{reason}");
        // No PATH at all: refused, never the C library's default path.
        assert!(
            super::resolve_bwrap(None)
                .unwrap_err()
                .contains("PATH is unset")
        );
    }

    /// §8.2: the version question spends what is left of the preparation
    /// budget, never a fresh probe deadline: a backend that does not answer
    /// refuses as the budget's timeout once the budget is spent.
    #[test]
    fn the_minimum_version_is_asked_within_the_preparation_budget() {
        let dir = tempfile::tempdir().unwrap();
        let slow = dir.path().join("bwrap");
        std::fs::write(&slow, b"#!/bin/sh\nexec sleep 30\n").unwrap();
        executable_mode(&slow);
        let started = std::time::Instant::now();
        let refusal =
            ask_minimum(&slow, clock::Deadline::after(Duration::from_millis(200))).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "asked for {:?}",
            started.elapsed()
        );
        assert_eq!(refusal.code, ErrorCode::PrepareTimeout);
        assert_eq!(refusal.remediation, Remediation::Retry);

        let old = dir.path().join("old-bwrap");
        std::fs::write(&old, b"#!/bin/sh\necho bubblewrap 0.9.0\n").unwrap();
        executable_mode(&old);
        let answer = ask_minimum(&old, clock::Deadline::after(Duration::from_secs(10))).unwrap();
        assert!(
            answer
                .as_ref()
                .is_err_and(|reason| reason.contains("0.9.0")),
            "{answer:?}"
        );
    }

    fn executable_mode(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn a_probe_never_executes_a_relative_or_missing_backend() {
        use super::super::probe::{self, ProbeStatus};
        let exe = std::path::Path::new("/nonexistent/ukai-jail");
        for (name, _) in probe::BACKEND_PROBES {
            for result in [
                probe::run_one(name, exe, std::path::Path::new("bwrap")),
                probe::run_one_backend(name, exe, Err("PATH is unset")),
            ] {
                // A table-bound probe is refused first on an architecture
                // the syscall tables do not cover.
                if result.status == ProbeStatus::Unsupported {
                    continue;
                }
                assert_eq!(result.status, ProbeStatus::Unavailable, "{name}");
                assert_eq!(result.reason_code, "backend_unavailable", "{name}");
            }
        }
    }

    pub(in crate::platform::linux) fn plan_request(
        profile: crate::policy::ProfileName,
        observe_off: bool,
    ) -> super::PlanRequest {
        let baseline = crate::profiles::baseline(profile, crate::records::Os::Linux, &|_| None);
        let inputs = crate::policy::ResolveInputs {
            platform: crate::records::Os::Linux,
            base_profile: profile,
            policy_name: profile.as_str().to_owned(),
            baseline,
            workspace: b"/work".to_vec(),
            scratch: crate::policy::ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        };
        let mut snapshot = crate::policy::resolve(&inputs)
            .expect("the built-in baseline resolves")
            .snapshot;
        if observe_off {
            snapshot.observation.mode = crate::records::ObserveMode::Off;
        }
        let requirements = crate::capability::requirements(&snapshot);
        super::PlanRequest {
            snapshot,
            requirements,
        }
    }

    /// §8.2: steps 3 to 5 spend what is left of the supervisor's one
    /// preparation budget. A plan whose budget is already spent refuses as
    /// the platform's own `prepare_timeout` (remediation `retry`), for both
    /// boundaries, before anything is built; a fresh budget of its own would
    /// go on to build one.
    #[test]
    fn a_spent_preparation_budget_refuses_before_any_boundary_is_built() {
        use crate::platform::{ContinuousDeadline, Platform as _, PreparedPlan, Sinks};
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        for profile in [ProfileName::Tool, ProfileName::None] {
            let workspace = root.join(format!("{}-workspace", profile.as_str()));
            let attempt_dir = root.join(format!("{}-attempt", profile.as_str()));
            std::fs::create_dir(&workspace).unwrap();
            std::fs::create_dir(&attempt_dir).unwrap();
            let marker = workspace.join("target-ran");
            let plan = PreparedPlan {
                attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
                attempt_dir,
                request: plan_request(profile, false),
                argv: vec![
                    b"/usr/bin/touch".to_vec(),
                    marker.as_os_str().as_bytes().to_vec(),
                ],
                prepare_deadline: ContinuousDeadline::after(Duration::ZERO),
                workspace,
                config_dir: root.join("config"),
                launch: None,
                proxy: None,
                pinned_roots: Vec::new(),
            };
            let Err(error) = LinuxPlatform::new().prepare(plan, Sinks { trace: None }) else {
                panic!("{profile:?}: a boundary was prepared on a spent budget");
            };
            assert_eq!(
                error.code,
                ErrorCode::PrepareTimeout,
                "{profile:?}: {error:?}"
            );
            assert_eq!(error.remediation, Remediation::Retry);
            assert!(!marker.exists(), "{profile:?}: the target ran");
            assert_eq!(
                std::fs::read_dir(root.join(format!("{}-attempt", profile.as_str())))
                    .unwrap()
                    .count(),
                0,
                "{profile:?}: preparation wrote into the attempt"
            );
        }
    }
}
