#![cfg(target_os = "linux")]
//! The descriptors a workspace's protected segments take are budgeted
//! before any is opened.
//!
//! Each protected segment is pinned (`O_PATH`) and its pin duplicated for
//! bubblewrap, so a workspace of a few hundred nested repositories needs
//! more descriptors than the 1024 a session's soft `RLIMIT_NOFILE` often
//! allows. The supervisor raises its soft limit to the hard one before
//! pinning, and refuses as a configuration only past the hard limit, never
//! failing half-way with `EMFILE` blamed on the host.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use ouro_fixture::harness::Jail;

mod common;

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// Sets this process's soft `RLIMIT_NOFILE` (the jail it spawns inherits
/// it) and puts the old one back on drop.
struct SoftNofile(libc::rlimit);

impl SoftNofile {
    fn set(soft: libc::rlim_t) -> SoftNofile {
        // SAFETY: an all-zero rlimit is a valid value the call overwrites.
        let mut old: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `old` is writable storage of the type getrlimit fills.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut old) };
        assert_eq!(rc, 0);
        let lowered = libc::rlimit {
            rlim_cur: soft.min(old.rlim_max),
            rlim_max: old.rlim_max,
        };
        // SAFETY: `lowered` is a valid rlimit that outlives the call, and
        // lowering the soft limit within the hard one needs no privilege.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lowered) };
        assert_eq!(rc, 0);
        SoftNofile(old)
    }
}

impl Drop for SoftNofile {
    fn drop(&mut self) {
        // SAFETY: restores the soft limit read at construction, which is
        // within the unchanged hard limit.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const self.0) };
    }
}

/// Attempted, live: a `tool` run over a workspace of 900 nested `.git`
/// directories (within the receipt's 1024-row mount bound) from a session
/// whose soft descriptor limit is 1024. Verdict: the pins fit after the
/// supervisor raises its soft limit, the run settles, and the target ran.
#[test]
fn nine_hundred_protected_segments_fit_a_1024_soft_descriptor_limit() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    for index in 0..900 {
        private_dir(&workspace.join(format!("r{index}/.git")));
    }
    let marker = workspace.join("target-ran");
    let _limit = SoftNofile::set(1024);
    let run = jail
        .arg("run")
        .arg("--profile")
        .arg("tool")
        .arg("--workspace")
        .arg(&workspace)
        .receipt()
        .target([
            OsString::from("/usr/bin/touch"),
            marker.clone().into_os_string(),
        ])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(marker.exists(), "the target did not run");
    let receipt = common::checked_receipt(
        run.receipt_phase("settled")
            .expect("a settled run writes a final receipt"),
    );
    assert_eq!(receipt["errors"], serde_json::json!([]), "{receipt:#}");
}

/// The same 1024 soft limit with 1100 segments: the receipt's mount bound,
/// not the descriptor limit, decides, and before anything is pinned.
#[test]
fn past_the_mount_bound_the_refusal_comes_before_any_pin() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    for index in 0..1100 {
        private_dir(&workspace.join(format!("r{index}/.git")));
    }
    let _limit = SoftNofile::set(1024);
    let run = jail
        .arg("run")
        .arg("--profile")
        .arg("tool")
        .arg("--workspace")
        .arg(&workspace)
        .receipt()
        .target([OsString::from("/usr/bin/true")])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(2), "{}", run.stderr_text());
    let receipt = common::checked_receipt(
        run.receipt_phase("refused")
            .expect("a refusal writes a final receipt"),
    );
    let error = &receipt["errors"][0];
    assert_eq!(error["code"], "invalid_config", "{receipt:#}");
    assert_eq!(error["remediation_category"], "configuration");
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains("hold 1104 protected segments") && message.contains("1024"),
        "{message}"
    );
}
