//! J5-D review F1/F2: bubblewrap is resolved once, to an absolute canonical
//! path, from the absolute entries of the operator's `PATH`, and only that
//! path is ever executed and recorded.
//!
//! The reviewer's probes, as regressions on the reference host:
//! - a `PATH` with an empty entry (which a shell-style lookup reads as the
//!   current directory) and a `./bwrap` in the working directory: that
//!   `bwrap` never runs, `doctor` records the real one;
//! - a relative entry holding a `bwrap`: skipped, never recorded as
//!   `rel/bwrap`;
//! - a `PATH` whose only entry is empty, and an unset `PATH`: no backend is
//!   resolved, so `doctor` is not ready, records `binaries.bwrap: null` and
//!   `bwrap_present` unavailable, and `run --profile tool` refuses with 125
//!   before exec, the planted `bwrap` never running. An unset `PATH` refuses
//!   rather than falling back to a built-in search path: the operator's
//!   `PATH` is the one provisioning point (§3.2), and the C library's default
//!   path is exactly the fallback that ran an unrecorded `/usr/bin/bwrap`.
//! - `/bin` on a merged-`/usr` host resolves to the canonical `/usr/bin/bwrap`.

#![cfg(target_os = "linux")]

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ouro_fixture::harness;
use serde_json::Value;

/// A private working directory holding a planted `bwrap` (at `./bwrap` and
/// at `./rel/bwrap`) that records each execution in a marker file and then
/// behaves as the real one, so a run through it would otherwise succeed.
struct Planted {
    root: tempfile::TempDir,
}

impl Planted {
    fn new() -> Self {
        let root = common::private_tempdir();
        let real = which_absolute("bwrap").expect("the reference host has bubblewrap");
        let marker = root.path().join("planted-bwrap-ran");
        let script = format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\nexec '{}' \"$@\"\n",
            marker.display(),
            real.display()
        );
        // The working directory (the run's workspace) is a sibling of the
        // state roots, as a real workspace would be.
        let work = root.path().join("work");
        for dir in [work.clone(), work.join("rel")] {
            std::fs::create_dir_all(&dir).expect("a directory");
            let path = dir.join("bwrap");
            std::fs::write(&path, &script).expect("the planted bwrap");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("executable");
        }
        for name in ["data", "config", "home"] {
            let path = root.path().join(name);
            std::fs::create_dir(&path).expect("a directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("private");
        }
        Planted { root }
    }

    fn work(&self) -> PathBuf {
        self.root.path().join("work")
    }

    fn marker(&self) -> PathBuf {
        self.root.path().join("planted-bwrap-ran")
    }

    fn ran(&self) -> Option<String> {
        std::fs::read_to_string(self.marker()).ok()
    }

    /// The jail with `PATH` set to `path` (or unset), run from the planted
    /// directory.
    fn jail(&self, path: Option<&str>, arguments: &[&str]) -> Output {
        let mut command = Command::new(harness::jail_path());
        command
            .env_clear()
            .env("HOME", self.root.path().join("home"))
            .env("OURO_DATA_DIR", self.root.path().join("data"))
            .env("OURO_CONFIG_DIR", self.root.path().join("config"))
            .current_dir(self.work())
            .args(arguments);
        for name in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        if let Some(path) = path {
            command.env("PATH", path);
        }
        command.output().expect("the jail runs")
    }

    fn doctor(&self, path: Option<&str>) -> (Value, Option<i32>) {
        let output = self.jail(path, &["doctor", "--json"]);
        let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "doctor --json prints one document ({error}): {}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (report, output.status.code())
    }
}

/// The first absolute `PATH` entry of this test process holding `name`.
fn which_absolute(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .filter(|dir| dir.is_absolute())
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn probe_row<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .find(|row| row["name"] == name)
        .unwrap_or_else(|| panic!("no {name} row: {report:#}"))
}

fn sha256_of(path: &Path) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(std::fs::read(path).expect("readable"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The real bubblewrap is recorded and the planted ones never run, whatever
/// sits in an empty or relative `PATH` entry.
#[test]
fn j5_empty_and_relative_path_entries_never_resolve_bubblewrap() {
    if !common::live() {
        return;
    }
    let planted = Planted::new();
    let real = std::fs::canonicalize("/usr/bin/bwrap").expect("the host's bubblewrap");
    for path in [":/usr/bin:/bin", "rel:/usr/bin:/bin", "/usr/bin::rel"] {
        let (report, code) = planted.doctor(Some(path));
        assert_eq!(planted.ran(), None, "PATH={path:?}: a planted bwrap ran");
        let recorded = &report["binaries"]["bwrap"];
        assert_eq!(
            recorded["path"],
            real.to_str().expect("UTF-8"),
            "PATH={path:?}: {recorded:#}"
        );
        assert_eq!(recorded["sha256"], sha256_of(&real), "PATH={path:?}");
        assert_eq!(probe_row(&report, "bwrap_present")["status"], "available");
        assert_eq!(
            code,
            Some(0),
            "PATH={path:?}: doctor ready on the reference host"
        );
    }
    // A contained run executes that same file, never the planted one.
    let target = planted.work().join("target-ran");
    let run = planted.jail(
        Some(":/usr/bin:/bin"),
        &[
            "run",
            "--profile",
            "tool",
            "--",
            "/usr/bin/touch",
            "target-ran",
        ],
    );
    assert_eq!(
        run.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(target.exists(), "the target ran");
    assert_eq!(planted.ran(), None, "the run executed a planted bwrap");
}

/// `/bin/bwrap` on a merged-`/usr` host is the same file as
/// `/usr/bin/bwrap`; the record names the canonical path that runs.
#[test]
fn j5_the_resolved_backend_is_canonical() {
    if !common::live() || !common::reference_host("the merged /usr layout") {
        return;
    }
    let planted = Planted::new();
    let (report, _) = planted.doctor(Some("/bin:/usr/bin"));
    assert_eq!(
        report["binaries"]["bwrap"]["path"],
        std::fs::canonicalize("/bin/bwrap")
            .expect("/bin/bwrap")
            .to_str()
            .expect("UTF-8")
    );
}

/// No absolute entry holds bubblewrap (only an empty entry, or no `PATH` at
/// all): nothing is resolved, nothing planted runs, `doctor` says so and a
/// contained run refuses before exec.
#[test]
fn j5_without_a_resolvable_backend_doctor_is_not_ready_and_run_refuses() {
    if !common::live() {
        return;
    }
    let planted = Planted::new();
    for path in [Some(":"), Some(""), Some("rel"), None] {
        let (report, code) = planted.doctor(path);
        assert_eq!(planted.ran(), None, "PATH={path:?}: a planted bwrap ran");
        assert_eq!(report["binaries"]["bwrap"], Value::Null, "PATH={path:?}");
        let present = probe_row(&report, "bwrap_present");
        assert_eq!(
            present["status"], "unavailable",
            "PATH={path:?}: {present:#}"
        );
        assert_eq!(present["reason_code"], "backend_unavailable");
        if path.is_none() {
            assert!(
                present["evidence_ref"]
                    .as_str()
                    .is_some_and(|evidence| evidence.contains("PATH is unset")),
                "{present:#}"
            );
        }
        // Every probe that would execute bubblewrap says why it did not.
        for name in ["user_namespace", "pid_namespace", "seccomp_filter_load"] {
            let row = probe_row(&report, name);
            assert_eq!(row["status"], "unavailable", "{name}: {row:#}");
            assert_eq!(row["reason_code"], "backend_unavailable", "{name}");
        }
        assert_eq!(report["ready"], false, "PATH={path:?}");
        assert_eq!(code, Some(125), "PATH={path:?}");

        let target = planted.work().join("target-ran");
        let run = planted.jail(
            path,
            &[
                "run",
                "--profile",
                "tool",
                "--",
                "/usr/bin/touch",
                "target-ran",
            ],
        );
        assert_eq!(run.status.code(), Some(125), "PATH={path:?}");
        assert!(!target.exists(), "PATH={path:?}: the target ran");
        assert_eq!(planted.ran(), None, "PATH={path:?}: a planted bwrap ran");
        assert!(
            String::from_utf8_lossy(&run.stderr).contains("backend_unavailable"),
            "PATH={path:?}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    }
}
