#![cfg(target_os = "linux")]
//! A refused preparation leaves the operator's workspace as it found it.
//!
//! jail-v1 §9.1: root-level protected literals are protected when absent, by
//! placeholder directories the supervisor creates in the workspace before
//! any mount, and it removes only unchanged, empty placeholders it created.
//! A preparation refused after that point (here the handoff verification,
//! one of many refusals that follow the mount preparation) must remove them
//! again rather than leave an empty `.git` or `.ukai` behind.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use ukai_fixture::harness::Jail;

mod common;

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// Attempted, live: a `tool` run over a workspace with neither root literal,
/// refused at the mount handoff by a protected directory added after the
/// scan (the `UKAI_JAIL_TEST_MOUNT_SWAP` seam opens the window). Verdict:
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
        .env("UKAI_JAIL_TEST_MOUNT_SWAP", &rendezvous)
        .receipt()
        .target([
            OsString::from("/usr/bin/touch"),
            marker.clone().into_os_string(),
        ])
        .spawn()
        .unwrap();

    common::eventually(
        "the mount-swap seam to signal `pinned`",
        common::SETTLE_BOUND,
        || rendezvous.join("pinned").exists(),
    );
    for literal in [".git", ".ukai"] {
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
    for literal in [".git", ".ukai"] {
        assert!(
            !workspace.join(literal).exists(),
            "the refused run left its {literal} placeholder in the workspace"
        );
    }
}

/// Attempted, live: a `tool` run over a workspace holding 1100 nested `.git`
/// directories, each bound read-only, which together pass the 1024 rows a
/// receipt's mount table records. Verdict: refused before anything is
/// spawned, as a configuration (`invalid_config`, remediation
/// `configuration`) that names the protected segments and the bound, never
/// as a host that cannot read its own mount table; the target never ran,
/// and the root placeholders the preparation made are gone.
#[test]
fn a_workspace_past_the_receipt_mount_bound_is_refused_as_configuration() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    for index in 0..1100 {
        private_dir(&workspace.join(format!("r{index}/.git")));
    }
    let marker = workspace.join("target-ran");
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
    assert_eq!(run.code(), Some(2), "{}", run.stderr_text());
    assert!(!marker.exists(), "the target ran");
    let receipt = common::checked_receipt(
        run.receipt_phase("refused")
            .expect("a refusal writes a final receipt"),
    );
    let error = &receipt["errors"][0];
    assert_eq!(error["code"], "invalid_config", "{receipt:#}");
    assert_eq!(error["remediation_category"], "configuration");
    let message = error["message"].as_str().unwrap();
    // The 1100 nested `.git`, and `.git` and `.ukai` at the root of the
    // workspace and of the managed scratch, held by placeholders.
    assert!(
        message.contains("hold 1104 protected segments")
            && message.contains("would hold at least")
            && message.contains("1024"),
        "{message}"
    );
    for literal in [".git", ".ukai"] {
        assert!(
            !workspace.join(literal).exists(),
            "the refused run left its {literal} placeholder in the workspace"
        );
    }
}

/// Attempted, live: `tool` runs over a workspace with neither root literal,
/// refused after the boundary was built and its namespace init found (a
/// storage ceiling of one byte cannot be admitted). The refusal kills the
/// tree, and the init's pidfd and the leaf report its death a little after
/// the kill. Verdict, every time: the refusal waited for that death inside
/// its budget and removed both placeholders, or its message names what it
/// left.
#[test]
fn a_refusal_after_the_boundary_exists_removes_the_placeholders_too() {
    if !common::live() {
        return;
    }
    for attempt in 0..10 {
        let jail = Jail::new().unwrap();
        let workspace = jail.root().join("workspace");
        private_dir(&workspace);
        let marker = workspace.join("target-ran");
        let run = jail
            .arg("run")
            .arg("--profile")
            .arg("tool")
            .arg("--workspace")
            .arg(&workspace)
            .args(["--limit", "storage=1"])
            .receipt()
            .target([
                OsString::from("/usr/bin/touch"),
                marker.clone().into_os_string(),
            ])
            .run()
            .unwrap();
        assert_eq!(run.code(), Some(125), "{attempt}: {}", run.stderr_text());
        assert!(!marker.exists(), "{attempt}: the target ran");
        let receipt = common::checked_receipt(
            run.receipt_phase("refused")
                .expect("a refusal writes a final receipt"),
        );
        let message = receipt["errors"][0]["message"].as_str().unwrap();
        assert!(
            message.contains("storage ceiling unavailable"),
            "{attempt}: not refused after the boundary was built: {message}"
        );
        for literal in [".git", ".ukai"] {
            assert!(
                !workspace.join(literal).exists(),
                "{attempt}: the refused run left its {literal} placeholder in the workspace: \
                 {message}"
            );
        }
    }
}
