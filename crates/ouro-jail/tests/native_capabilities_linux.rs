//! Optional kernel facilities must either work or refuse before the child runs.
#![cfg(target_os = "linux")]

use ouro_fixture::harness::{self, Jail};
use serde_json::Value;
use std::process::Command;

mod common;

#[test]
fn a_required_memory_ceiling_runs_only_when_the_host_can_enforce_it() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let doctor = Command::new(harness::jail_path())
        .args(["doctor", "--json"])
        .env("OURO_CONFIG_DIR", jail.config_dir())
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    let memory = report["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "cgroup_memory")
        .expect("measured memory controller");
    let available = memory["status"] == "available";
    let run = jail
        .args(["run", "--profile", "build", "--workspace"])
        .arg(&workspace)
        .args(["--limit", "mem=64MiB", "--limit", "wall=5s"])
        .target(["/bin/sh", "-c", "printf memory-ceiling-child-ran"])
        .run()
        .unwrap();
    if available {
        assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
        assert!(run.stdout_text().contains("memory-ceiling-child-ran"));
    } else {
        assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
        assert!(!run.stdout_text().contains("memory-ceiling-child-ran"));
        assert!(
            run.stderr_text().contains("missing_capability"),
            "{}",
            run.stderr_text()
        );
        eprintln!(
            "host memory controller unavailable; required ceiling refused before exec: {memory}"
        );
    }
}

#[test]
fn a_requested_landlock_domain_is_installed_or_refuses_before_exec() {
    // SAFETY: the VERSION query reads no pointers and changes no process state.
    let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0, 0, 1) };
    let output = Command::new(harness::fixture_path())
        .args([
            "sandbox-exec",
            "--landlock-ro",
            "/",
            "--",
            "/bin/sh",
            "-c",
            "printf landlock-child-ran",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    if abi > 0 {
        assert!(output.status.success(), "{stdout}");
        assert!(stdout.contains("landlock-child-ran"));
    } else {
        assert_eq!(output.status.code(), Some(3), "{stdout}");
        assert!(!stdout.contains("landlock-child-ran"));
        assert!(stdout.contains("landlock_create_ruleset"), "{stdout}");
        eprintln!("host Landlock unavailable; requested domain refused before exec");
    }
}
