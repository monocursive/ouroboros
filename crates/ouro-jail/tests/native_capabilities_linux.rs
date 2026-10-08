//! Optional kernel facilities must either work or refuse before the child runs.
#![cfg(target_os = "linux")]

use ouro_fixture::harness::{self, Jail};
use serde_json::Value;
use std::process::Command;

mod common;

#[test]
fn an_agent_requires_unix_socket_diagnostics_before_exec() {
    if !common::live() {
        return;
    }
    let diagnostics =
        ouro_jail::platform::linux::sockdiag::SockDiag::open().and_then(|mut socket| {
            socket.dump(ouro_jail::platform::linux::sockdiag::UDIAG_SHOW_VFS, -1)
        });
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let run = jail
        .args(["run", "--profile", "agent", "--workspace"])
        .arg(&workspace)
        .args(["--limit", "wall=5s"])
        .target(["/bin/sh", "-c", "printf agent-child-ran"])
        .run()
        .unwrap();
    if diagnostics.is_ok() {
        assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
        assert!(run.stdout_text().contains("agent-child-ran"));
    } else {
        assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
        assert!(!run.stdout_text().contains("agent-child-ran"));
        assert!(
            run.stderr_text()
                .contains("unix_socket_diagnostics_unavailable"),
            "{}",
            run.stderr_text()
        );
        eprintln!(
            "host AF_UNIX diagnostics unavailable; agent refused before exec: {diagnostics:?}"
        );
    }
}

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
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let protected = workspace.join("protected.txt");
    std::fs::write(&protected, b"outside the inner grant").unwrap();
    let doctor = Command::new(harness::jail_path())
        .args(["doctor", "--json"])
        .env("OURO_CONFIG_DIR", jail.config_dir())
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    let inner = report["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "agent_inner_sandbox")
        .expect("measured agent inner sandbox");
    let available = inner["status"] == "available";
    // One real `agent` run whose target requests a Landlock domain over a
    // fresh scratch grant and read-only `/usr` — the probe's own scripted
    // sandbox — and then reports the raw result of reading and writing a
    // workspace file that lies outside both grants.
    let run = jail
        .args(["run", "--profile", "agent", "--workspace"])
        .arg(&workspace)
        .args(["--limit", "wall=10s"])
        .arg("--")
        .arg(ouro_jail::platform::linux::bwrap::JAIL_INSIDE_PATH)
        .arg(ouro_jail::platform::linux::probe::INSIDE_SUBCOMMAND)
        .arg(format!("inner=inner:{}", protected.display()))
        .run()
        .unwrap();
    let stdout = run.stdout_text();
    if available {
        // The requested domain installs and enforces: the protected file's
        // reads and writes are denied from inside the child itself.
        assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
        assert!(stdout.contains("inner=landlock:ok"), "{stdout}");
        assert!(stdout.contains("write:EACCES"), "{stdout}");
        assert!(stdout.contains("read:EACCES"), "{stdout}");
    } else {
        // Measured unavailable: either the `agent` profile refuses before
        // exec, or the requested domain fails visibly to the child. The jail
        // never reports a domain that did not install.
        assert!(
            !stdout.contains("landlock:ok"),
            "doctor measured the inner sandbox unavailable, but the child installed it: {stdout}"
        );
        eprintln!(
            "host Landlock inner sandbox unavailable; the requested domain did not install: {inner}"
        );
    }
}
