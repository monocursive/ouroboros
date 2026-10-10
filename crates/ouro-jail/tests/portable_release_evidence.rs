//! Recorded real-vendor and clean-VM evidence stays bound to current Jail inputs.
use std::path::Path;
use std::process::Command;

fn recorded(check: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = Command::new("python3")
        .arg(root.join("docs/benchmarks/jail/verify_preview_evidence.py"))
        .arg("--directory")
        .arg(root.join("docs/benchmarks/jail/results/release-preview-2026-10-10"))
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
