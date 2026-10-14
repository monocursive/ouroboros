#![cfg(target_os = "linux")]
//! A refused preparation leaves the operator's workspace as it found it.
//!
//! jail-v1 §9.1: root-level protected literals are protected when absent, by
//! placeholder directories the supervisor creates in the workspace before
//! any mount, and it removes only unchanged, empty placeholders it created.
//! A preparation refused after that point (here the handoff verification,
//! one of many refusals that follow the mount preparation) must remove them
//! again rather than leave an empty `.git` or `.ouroboros` behind.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use ouro_fixture::harness::Jail;

mod common;

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// Attempted, live: a `tool` run over a workspace with neither root literal,
/// refused at the mount handoff by a protected directory added after the
/// scan (the `OURO_JAIL_TEST_MOUNT_SWAP` seam opens the window). Verdict:
/// the placeholders existed while the run prepared, and the refusal (125, no
/// target) removed both.
#[test]
fn a_refusal_after_the_placeholders_were_made_removes_them() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    let nested = workspace.join("nested");
    private_dir(&nested);
    let rendezvous = jail.root().join("swap-rv");
    private_dir(&rendezvous);
    let marker = workspace.join("target-ran");
    let spawned = jail
        .arg("run")
        .arg("--profile")
        .arg("tool")
        .arg("--workspace")
        .arg(&workspace)
        .env("OURO_JAIL_TEST_MOUNT_SWAP", &rendezvous)
        .receipt()
        .target([
            OsString::from("/usr/bin/touch"),
            marker.clone().into_os_string(),
        ])
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(20);
    while !rendezvous.join("pinned").exists() {
        assert!(
            Instant::now() < deadline,
            "the mount-swap seam never signalled `pinned`"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    for literal in [".git", ".ouroboros"] {
        assert!(
            workspace.join(literal).is_dir(),
            "precondition: the {literal} placeholder exists while the run prepares"
        );
    }
    private_dir(&nested.join(".git"));
    std::fs::write(rendezvous.join("go"), b"1").unwrap();

    let run = spawned.wait().unwrap();
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    assert!(!marker.exists(), "the target ran with an incomplete scan");
    for literal in [".git", ".ouroboros"] {
        assert!(
            !workspace.join(literal).exists(),
            "the refused run left its {literal} placeholder in the workspace"
        );
    }
}
