//! Missing Linux developer-release proofs, through actual CLI executions.
#![cfg(target_os = "linux")]
use std::path::Path;
use std::process::Command;
mod common;

fn preview_case(case: &str) {
    if !common::live() {
        return;
    }
    let result = Command::new("python3")
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/benchmarks/jail/preview_gates.py"),
        )
        .args(["--binary", env!("CARGO_BIN_EXE_ouro-jail"), "--case", case])
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
fn k03_none_refuses_each_trusted_file_and_runs_without_them() {
    preview_case("none");
}
#[test]
fn k10_adoption_requires_a_tty_and_consent_rechecks_then_replaces_atomically() {
    preview_case("adopt");
}
#[test]
fn k19_k20_live_follow_is_prompt_and_replay_is_byte_identical() {
    preview_case("tail");
}
#[test]
fn k16_vault_requires_origins_and_records_no_staged_secret_or_digest() {
    preview_case("vault");
}

#[test]
fn k27_signed_installer_rejects_corruption_without_a_terminal() {
    let result = Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("dist/test_install.py"))
        .arg(env!("CARGO_BIN_EXE_ouro-jail"))
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
