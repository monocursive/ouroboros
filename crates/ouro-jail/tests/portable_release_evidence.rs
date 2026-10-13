//! Recorded real-vendor and clean-VM evidence stays bound to current Jail inputs.
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRecord {
    directory: PathBuf,
}

fn recorded(check: &str) {
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
        .args(["--inputs", env!("OURO_BUILD_INPUTS"), "--check", check])
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
