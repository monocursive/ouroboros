//! Shared test support.
//!
//! Not a test target: Cargo builds only the top-level `.rs` files in `tests/`,
//! so this is compiled into each binary that declares `mod common;`.

// Each binary uses the part of this module it needs; the rest is not dead so
// much as unused by that particular binary.
#![allow(dead_code)]

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt as _;

use tempfile::TempDir;

/// A temporary directory created mode 0700, whatever the umask is.
///
/// `tempfile::tempdir()` creates with 0777 masked by the process umask, so the
/// result is 0755 on a host whose umask is 022 and 0775 on one whose umask is
/// 002. A state root under a group-writable ancestor is refused by
/// `state::check_state_ancestors`, and rightly: §6.2 rejects "unsafe parent
/// replacement", and anyone in that group can swap the next component for
/// their own. The check stays strict; the tests stop handing it a directory
/// that fails it for reasons that have nothing to do with what they test.
///
/// Every test file uses this, not only the ones that build a state root today:
/// which temporary directory ends up as a state-root ancestor is a detail that
/// changes when a test is edited, and the umask of the machine running it is
/// not something a test should depend on either way.
pub fn private_tempdir() -> TempDir {
    tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .expect("a temporary directory")
}

// ---------------------------------------------------------------------------
// The precondition every live Linux check shares
// ---------------------------------------------------------------------------

//
// jail-v1 §16: a generic hosted runner runs the portable tests and never
// pretends to exercise a privileged kernel feature. A check that needs the
// backend and a user namespace says so and skips where it cannot have them,
// and under `OURO_CONFORMANCE=1` — the provisioned host — the same call fails
// instead, because there a missing capability is a real result. One answer to
// "can this host run these?", shared by all three Linux test binaries.

use std::path::PathBuf;
use std::sync::OnceLock;

use ouro_fixture::harness;

/// What the probe established, once per process.
struct Preconditions {
    /// The backend, when it is on `PATH` and works.
    bwrap: Option<PathBuf>,
    /// Why the live checks cannot run here, when they cannot.
    reason: Option<String>,
}

fn preconditions() -> &'static Preconditions {
    static ONCE: OnceLock<Preconditions> = OnceLock::new();
    ONCE.get_or_init(measure)
}

/// Whether this host can run the live checks.
///
/// Prints `skipped: <reason>` and returns false when it cannot, or fails when
/// `OURO_CONFORMANCE=1` says a skip is not an answer. Call it first in every
/// test that needs the backend, and return when it is false.
#[must_use]
pub fn live() -> bool {
    match preconditions().reason.as_deref() {
        None => true,
        Some(reason) => {
            harness::skip_or_fail(reason);
            false
        }
    }
}

/// The backend this host's live checks use.
///
/// Only meaningful after [`live`] returned true; it never panics, so a caller
/// that forgets gets a failed run rather than a confusing one.
#[must_use]
pub fn bwrap_path() -> PathBuf {
    preconditions()
        .bwrap
        .clone()
        .unwrap_or_else(|| PathBuf::from("bwrap"))
}

/// A claim about the provisioned reference host rather than about Linux.
///
/// The merged-`/usr` layout and the delegated cgroup subtree are properties of
/// the host §3.2 pins, not of the kernel: a generic runner can have the
/// backend and still not be that host. Such a check runs under
/// `OURO_CONFORMANCE=1`, where it is judged, and skips elsewhere with the
/// reason. It is not made conditional on its own assertion, which would be a
/// check that cannot fail.
#[must_use]
pub fn reference_host(what: &str) -> bool {
    if harness::live_required() {
        return true;
    }
    harness::skip_or_fail(&format!(
        "{what} is a property of the provisioned reference host; \
         set OURO_CONFORMANCE=1 on that host to check it"
    ));
    false
}

/// Measure, without panicking, whether the live checks can run.
///
/// Off Linux there is nothing to measure: the mechanisms these checks are
/// about do not exist, and the modules that would probe them are not compiled.
#[cfg(not(target_os = "linux"))]
fn measure() -> Preconditions {
    unmet("these checks measure Linux kernel mechanisms")
}

/// Measure, without panicking, whether the live checks can run.
#[cfg(target_os = "linux")]
fn measure() -> Preconditions {
    use std::path::Path;
    use std::process::Command;
    use std::time::Duration;

    let Some(bwrap) = which("bwrap") else {
        return unmet("bubblewrap is not on PATH, so there is no backend to measure");
    };
    let Some(truth) = ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
    else {
        return unmet("this host has no `true` to run inside a sandbox");
    };

    // The binary alone is not the question. A hosted runner can have
    // bubblewrap and still refuse an unprivileged user namespace, which is
    // the capability every one of these checks rests on, so the probe creates
    // one and runs a command in it.
    let mut command = Command::new(&bwrap);
    command.arg("--unshare-user").arg("--unshare-pid");
    for root in ouro_jail::platform::linux::bwrap::RUNTIME_ROOTS
        .iter()
        .filter_map(|path| ouro_jail::platform::linux::fs::resolve_runtime_root(Path::new(path)))
    {
        match root {
            ouro_jail::platform::linux::fs::RootSpec::RoBind(path) => {
                command.arg("--ro-bind").arg(&path).arg(&path);
            }
            ouro_jail::platform::linux::fs::RootSpec::Symlink { path, target } => {
                command.arg("--symlink").arg(&target).arg(&path);
            }
        }
    }
    command.arg("--proc").arg("/proc").arg("--").arg(&truth);

    let deadline = ouro_jail::platform::linux::clock::Deadline::after(Duration::from_secs(10));
    match ouro_jail::platform::linux::exec::run_captured(&mut command, deadline) {
        Ok(run) if run.status.success() => Preconditions {
            bwrap: Some(bwrap),
            reason: None,
        },
        Ok(run) if run.timed_out => unmet("a sandbox probe did not finish in ten seconds"),
        Ok(run) => {
            let detail = run
                .stderr
                .lines()
                .next()
                .unwrap_or("no diagnostic")
                .to_owned();
            unmet(&format!(
                "this host refuses an unprivileged user and pid namespace: {detail}"
            ))
        }
        Err(error) => unmet(&format!("the sandbox probe could not be started: {error}")),
    }
}

fn unmet(reason: &str) -> Preconditions {
    Preconditions {
        bwrap: None,
        reason: Some(reason.to_owned()),
    }
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    })
}
