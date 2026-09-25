#![cfg(target_os = "linux")]
//! S02 (jail-v1 §9.1): an operator grant may not expose host `/proc`, `/sys`
//! or cgroupfs. The late-wave review (rev-late F5) showed a contained `tool`
//! run accepting `--ro /proc`, `--ro /sys` and `--ro /sys/fs/cgroup` and
//! settling enforced/enforced. Each grant, and a symlink spelling of one,
//! must refuse before exec, by the resolved source's filesystem type, not by
//! path spelling; `--ro /` (an ancestor of those mounts) must refuse too.
//!
//! Live on the reference host; under `OURO_CONFORMANCE=1` a skip is a failure.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use ouro_fixture::harness::{self, Jail, Run};

mod common;

/// A `run --profile <profile>` over a private workspace holding the fixture.
struct Case {
    jail: Jail,
    workspace: PathBuf,
    fixture: PathBuf,
}

fn case(profile: &str) -> Case {
    use std::os::unix::fs::PermissionsExt as _;
    let jail = Jail::new().expect("a private jail harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir_all(&workspace).expect("the workspace");
    let fixture = workspace.join("ouro-fixture");
    std::fs::copy(harness::fixture_path(), &fixture).expect("the fixture is copied in");
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755))
        .expect("the fixture is executable");
    let jail = jail
        .arg("run")
        .args(["--profile", profile])
        .arg("--workspace")
        .arg(&workspace)
        .trace()
        .control();
    Case {
        jail,
        workspace,
        fixture,
    }
}

/// One `--ro GRANT` run whose target would create `marker`: its exit code,
/// stderr, and whether the marker appeared.
fn ro_grant_run(profile: &str, grant: &Path) -> (Option<i32>, String, bool) {
    let c = case(profile);
    let marker = c.workspace.join("target-ran");
    let run: Run = c
        .jail
        .arg("--ro")
        .arg(grant)
        .target([
            c.fixture.as_os_str(),
            OsStr::new("open"),
            marker.as_os_str(),
            OsStr::new("--create"),
            OsStr::new("--write"),
        ])
        .run()
        .expect("the jail runs");
    (run.code(), run.stderr_text(), marker.exists())
}

/// §9.1: a contained profile refuses an operator grant that exposes host
/// `/proc`, `/sys` or cgroupfs — the three the review accepted — before exec,
/// with a policy refusal (exit 125) naming the grant's key path. The
/// enforcement point a mutation deletes is the pseudo-filesystem guard the
/// Linux platform runs over the resolved operator grants before mounting.
#[test]
fn s02_a_contained_grant_of_proc_sys_or_cgroupfs_refuses_before_exec() {
    if !common::live() {
        return;
    }
    // `/proc/1` is strictly inside the proc mount, not a mount point itself,
    // so only the source's filesystem type (statfs) catches it; the three
    // mount points are also caught by mount topology. Together they exercise
    // both branches of the guard.
    let grants: &[&str] = &["/proc", "/sys", "/sys/fs/cgroup", "/proc/1"];
    for profile in ["tool", "agent"] {
        for grant in grants {
            if !Path::new(grant).exists() {
                continue;
            }
            let (code, stderr, ran) = ro_grant_run(profile, Path::new(grant));
            assert_eq!(code, Some(125), "{profile} --ro {grant}: {stderr}");
            assert!(!ran, "{profile} --ro {grant}: the target ran");
            assert!(
                stderr.contains("policy_widening")
                    && stderr.contains("(key: filesystem.read_only)"),
                "{profile} --ro {grant}: {stderr}"
            );
            assert!(
                stderr.contains(grant),
                "{profile} --ro {grant}: the refusal does not name the grant: {stderr}"
            );
        }
    }
}

/// The refusal is by the resolved source's filesystem type, not its spelling:
/// a symlink whose target is `/proc` refuses the same way, and `--ro /`, an
/// ancestor of the pseudo mounts, refuses too. A grant of an ordinary
/// directory on the root filesystem is accepted, so the guard is not refusing
/// every grant.
#[test]
fn s02_the_pseudo_fs_refusal_follows_the_source_not_the_spelling() {
    if !common::live() {
        return;
    }
    // A symlink to /proc, named so its own spelling says nothing.
    let c = case("tool");
    let link = c.workspace.join("innocent");
    std::os::unix::fs::symlink("/proc", &link).expect("the symlink");
    let marker = c.workspace.join("target-ran");
    let run = c
        .jail
        .arg("--ro")
        .arg(&link)
        .target([
            c.fixture.as_os_str(),
            OsStr::new("open"),
            marker.as_os_str(),
            OsStr::new("--create"),
            OsStr::new("--write"),
        ])
        .run()
        .expect("the jail runs");
    assert_eq!(
        run.code(),
        Some(125),
        "symlink to /proc: {}",
        run.stderr_text()
    );
    assert!(!marker.exists(), "symlink to /proc: the target ran");
    assert!(
        run.stderr_text().contains("policy_widening"),
        "symlink to /proc: {}",
        run.stderr_text()
    );

    // `--ro /`: an ancestor of every pseudo mount, refused before exec. On a
    // stock host the state root lives under `/`, so the state-isolation rule
    // (a child-visible root may not contain the state root) refuses it first,
    // with `unsafe_state_path`; either way it never runs and the pseudo-fs
    // guard's ancestor branch is covered by the portable rule test. What
    // matters here is that `--ro /` does not reach the target.
    let (code, stderr, ran) = ro_grant_run("tool", Path::new("/"));
    assert_eq!(code, Some(125), "--ro /: {stderr}");
    assert!(!ran, "--ro /: the target ran");
    assert!(
        stderr.contains("unsafe_state_path") || stderr.contains("policy_widening"),
        "--ro / refused for an unexpected reason: {stderr}"
    );

    // An ordinary directory on the root filesystem is still accepted (the
    // guard refuses pseudo filesystems, not every grant). It sits inside the
    // workspace so it does not overlap the private state root.
    let ordinary = case("tool");
    let allowed = ordinary.workspace.join("inputs");
    std::fs::create_dir(&allowed).expect("the ordinary grant directory");
    let marker = ordinary.workspace.join("target-ran");
    let run = ordinary
        .jail
        .arg("--ro")
        .arg(&allowed)
        .target([
            ordinary.fixture.as_os_str(),
            OsStr::new("open"),
            marker.as_os_str(),
            OsStr::new("--create"),
            OsStr::new("--write"),
        ])
        .run()
        .expect("the jail runs");
    assert_eq!(
        run.code(),
        Some(0),
        "an ordinary --ro grant: {}",
        run.stderr_text()
    );
    assert!(marker.is_file(), "the ordinary run did not execute");
}
