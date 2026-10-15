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

use ukai_fixture::harness::Jail;

mod common;

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
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
    let _limit = common::SoftNofile::set(1024);
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
/// not the descriptor limit, decides, and before anything is pinned or any
/// placeholder made: the refusal says so (a later check of the same bound
/// does not), and the workspace has no placeholder for its absent root
/// literals.
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
    let _limit = common::SoftNofile::set(1024);
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
    assert!(
        message.contains("before any protected segment was pinned or any placeholder made"),
        "not the refusal before pinning: {message}"
    );
    for literal in [".git", ".ukai"] {
        assert!(
            !workspace.join(literal).exists(),
            "the refusal left a {literal} placeholder in the workspace"
        );
    }
}
