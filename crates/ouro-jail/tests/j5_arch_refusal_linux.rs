//! J5-D review F12: the architecture refusal, end to end through `doctor`
//! and `run`, on the reference host, with the architecture injected by the
//! `OURO_JAIL_TEST_ARCH` seam (a real aarch64 Linux run is a later lane,
//! jail-v1 §3.2; the seam only ever adds the refusal a build for that
//! architecture makes, and its evidence names the seam).

#![cfg(target_os = "linux")]

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output};

use ouro_fixture::harness;
use serde_json::Value;

struct Dirs {
    root: tempfile::TempDir,
}

impl Dirs {
    fn new() -> Self {
        let root = common::private_tempdir();
        for name in ["data", "config", "home", "work"] {
            let path = root.path().join(name);
            std::fs::create_dir(&path).expect("a directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("private");
        }
        Dirs { root }
    }

    fn work(&self) -> PathBuf {
        self.root.path().join("work")
    }

    fn jail(&self, arch: Option<&str>, arguments: &[&str]) -> Output {
        let mut command = Command::new(harness::jail_path());
        command
            .env("HOME", self.root.path().join("home"))
            .env("OURO_DATA_DIR", self.root.path().join("data"))
            .env("OURO_CONFIG_DIR", self.root.path().join("config"))
            .env_remove("OURO_JAIL_TEST_ARCH")
            .current_dir(self.work())
            .args(arguments);
        if let Some(arch) = arch {
            command.env("OURO_JAIL_TEST_ARCH", arch);
        }
        command.output().expect("the jail runs")
    }
}

fn row<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .find(|row| row["name"] == name)
        .unwrap_or_else(|| panic!("no {name} row: {report:#}"))
}

#[test]
fn j5_an_aarch64_build_is_not_ready_and_refuses_contained_runs_before_exec() {
    if !common::live() {
        return;
    }
    let dirs = Dirs::new();
    let doctor = dirs.jail(Some("aarch64"), &["doctor", "--json"]);
    assert_eq!(doctor.status.code(), Some(125), "doctor is not ready");
    let report: Value = serde_json::from_slice(&doctor.stdout).expect("doctor --json");
    for name in [
        "seccomp_filter_load",
        "observer_closed_set",
        "seccomp_user_notification",
        "agent_proxy_bridge",
        "agent_unix_peer_mediation",
        "agent_inner_sandbox",
        "syscall_filter",
        "closed_set_observation",
    ] {
        let row = row(&report, name);
        assert_eq!(row["status"], "unsupported", "{name}: {row:#}");
        assert_eq!(row["reason_code"], "unsupported_architecture", "{name}");
    }
    assert!(
        row(&report, "seccomp_filter_load")["evidence_ref"]
            .as_str()
            .is_some_and(|evidence| evidence.contains("OURO_JAIL_TEST_ARCH=aarch64")),
        "the refusal names the seam"
    );
    // Rows that rest on no syscall table are measured as usual.
    assert_eq!(row(&report, "bwrap_present")["status"], "available");
    assert_eq!(report["ready"], false);

    // A contained run refuses with 125 before exec; the target never runs.
    let target = dirs.work().join("target-ran");
    for profile in ["tool", "build", "agent"] {
        let mut arguments = vec!["run", "--profile", profile];
        if profile == "build" {
            arguments.extend(["--limit", "mem=1GiB"]);
        }
        arguments.extend(["--", "/usr/bin/touch", "target-ran"]);
        let run = dirs.jail(Some("aarch64"), &arguments);
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert_eq!(run.status.code(), Some(125), "{profile}: {stderr}");
        assert!(
            stderr.contains("unsupported_architecture"),
            "{profile}: {stderr}"
        );
        assert!(!target.exists(), "{profile}: the target ran");
    }
    // `none` with observation off rests on no table and still runs.
    let none = dirs.jail(
        Some("aarch64"),
        &[
            "run",
            "--profile",
            "none",
            "--observe",
            "off",
            "--",
            "/usr/bin/touch",
            "target-ran",
        ],
    );
    assert_eq!(
        none.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&none.stderr)
    );
    assert!(target.exists(), "none ran");
}

/// The seam cannot lift a refusal: naming the covered architecture (or
/// nothing) changes nothing on this x86_64 build.
#[test]
fn j5_the_arch_seam_never_grants() {
    if !common::live() {
        return;
    }
    let dirs = Dirs::new();
    for arch in [None, Some("x86_64"), Some("")] {
        let doctor = dirs.jail(arch, &["doctor", "--json"]);
        let report: Value = serde_json::from_slice(&doctor.stdout).expect("doctor --json");
        assert_eq!(
            row(&report, "seccomp_filter_load")["status"],
            "available",
            "{arch:?}"
        );
        assert_eq!(doctor.status.code(), Some(0), "{arch:?}");
    }
}
