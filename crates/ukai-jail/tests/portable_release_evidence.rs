//! Recorded real-vendor and clean-VM evidence stays bound to current Jail inputs.
//!
//! A release gate (K11, K27), not a development check: the records name the
//! exact build inputs of the binary they ran, so any edit under
//! `crates/ukai-jail/src` makes them stale until a new clean-VM run is
//! recorded. The checks run only with `UKAI_RELEASE_EVIDENCE=1`, which the
//! conformance driver and the release workflow set; otherwise the tests skip,
//! and under `UKAI_CONFORMANCE=1` that skip is a failure. The records are of
//! a Linux VM and their clauses are judged in the Linux lane only, so the
//! file is Linux-only: the macOS lane runs in conformance mode without them.
#![cfg(target_os = "linux")]

use std::path::{Component, Path, PathBuf};
use std::process::Command;

use ukai_fixture::harness;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRecord {
    directory: PathBuf,
}

fn recorded(check: &str) {
    if !harness::release_evidence_requested() {
        harness::skip_or_fail(&format!(
            "the recorded release evidence ({check}) is checked only with {}=1",
            harness::RELEASE_EVIDENCE_VAR
        ));
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Select a fresh retained record without replacing historical evidence.
    // The verifier still requires this compiled binary's exact input digest.
    let record: PreviewRecord = serde_json::from_slice(
        &std::fs::read(root.join("docs/benchmarks/jail/release-preview-current.json"))
            .expect("the current preview evidence index"),
    )
    .expect("a current preview record");
    assert!(
        record.directory.starts_with("results")
            && record
                .directory
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "preview evidence must name a retained directory under results"
    );
    let result = Command::new("python3")
        .arg(root.join("docs/benchmarks/jail/verify_preview_evidence.py"))
        .arg("--directory")
        .arg(root.join("docs/benchmarks/jail").join(record.directory))
        .args(["--inputs", env!("UKAI_BUILD_INPUTS"), "--check", check])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn k11_recorded_real_opencode_learning_proposes_only_evidence_supported_grants() {
    recorded("learning");
}

#[test]
fn k27_clean_vm_install_true_and_real_opencode_finish_within_ten_minutes() {
    recorded("onboarding");
}
