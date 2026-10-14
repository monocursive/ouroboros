#![cfg(target_os = "linux")]
//! A session whose soft descriptor limit is below the supervisor's
//! descriptor range.
//!
//! The supervisor hands descriptors to its children at fixed numbers, from
//! duplicates it keeps at 256 and above (`exec::FdMap`). `F_DUPFD` refuses a
//! start at or above the soft `RLIMIT_NOFILE` with `EINVAL`, so a session
//! whose soft limit is 256 or less refused every observed run and `doctor`
//! named nothing but "Invalid argument". The supervisor now raises its own
//! soft limit to the hard one first, and the launcher still hands the target
//! the operator's.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

use ouro_fixture::harness::{self, Jail};
use serde_json::Value;

mod common;

/// The soft limit every run here starts from: below the 256 the supervisor
/// keeps its handed-on descriptors at.
const OPERATOR_SOFT: libc::rlim_t = 200;

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// This process's `RLIMIT_NOFILE`, lowered for the test and put back after.
struct SoftNofile(libc::rlimit);

impl SoftNofile {
    fn read() -> libc::rlimit {
        // SAFETY: an all-zero rlimit is a valid value the call overwrites.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `limit` is writable storage of the type getrlimit fills.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) },
            0
        );
        limit
    }

    fn set(soft: libc::rlim_t) -> SoftNofile {
        let old = SoftNofile::read();
        let lowered = libc::rlimit {
            rlim_cur: soft.min(old.rlim_max),
            rlim_max: old.rlim_max,
        };
        // SAFETY: a valid rlimit that outlives the call; lowering the soft
        // limit within the hard one needs no privilege.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lowered) },
            0
        );
        SoftNofile(old)
    }
}

impl Drop for SoftNofile {
    fn drop(&mut self) {
        // SAFETY: restores the limit read at construction, within the
        // unchanged hard limit.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const self.0) };
    }
}

/// Whether the hard limit leaves the supervisor room above its range.
fn room_to_raise() -> bool {
    let room = SoftNofile::read().rlim_max > 1024;
    if !room {
        harness::skip_or_fail("the hard RLIMIT_NOFILE leaves no room above the supervisor's range");
    }
    room
}

/// The soft `Max open files` the target of a `profile` run, observed,
/// reads from its own `/proc/self/limits`, from a session whose soft limit
/// is [`OPERATOR_SOFT`].
fn target_soft_limit(profile: &str) -> String {
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    private_dir(&workspace);
    let marker = workspace.join("limits");
    let _soft = SoftNofile::set(OPERATOR_SOFT);
    let run = jail
        .arg("run")
        .arg("--profile")
        .arg(profile)
        .arg("--observe")
        .arg("on")
        .arg("--workspace")
        .arg(&workspace)
        .receipt()
        .target([
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(format!(
                "grep 'Max open files' /proc/self/limits > {}",
                marker.display()
            )),
        ])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{profile}: {}", run.stderr_text());
    common::settled(&run);
    let line = std::fs::read_to_string(&marker).unwrap();
    // `Max open files  <soft>  <hard>  files`
    line.split_whitespace()
        .nth(3)
        .unwrap_or_else(|| panic!("no soft limit in {line:?}"))
        .to_owned()
}

/// Attempted, live: an observed `tool`, `agent` and `none` run each, from a
/// session whose soft descriptor limit is 200. Verdict: every run settles,
/// and every target reads the operator's 200.
#[test]
fn an_observed_run_works_below_the_supervisors_descriptor_range() {
    if !common::live() || !room_to_raise() {
        return;
    }
    for profile in ["tool", "agent", "none"] {
        assert_eq!(
            target_soft_limit(profile),
            OPERATOR_SOFT.to_string(),
            "{profile}"
        );
    }
}

/// Attempted, live: `doctor` from a session whose soft descriptor limit is
/// 200. Verdict: the observer probe, which hands the launcher its channels
/// like a run does, measures the host instead of failing.
#[test]
fn doctor_measures_the_observer_below_the_supervisors_descriptor_range() {
    if !common::live() || !room_to_raise() {
        return;
    }
    let jail = Jail::new().unwrap();
    let _soft = SoftNofile::set(OPERATOR_SOFT);
    let out = Command::new(harness::jail_path())
        .arg("doctor")
        .arg("--json")
        .env("OURO_DATA_DIR", jail.data_dir())
        .env("OURO_CONFIG_DIR", jail.config_dir())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let report: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"));
    let probe = report["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|capability| capability["name"] == "observer_closed_set")
        .unwrap_or_else(|| panic!("no observer probe: {report:#}"));
    assert_eq!(probe["status"], "available", "{probe:#}");
}
