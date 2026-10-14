#![cfg(target_os = "linux")]
//! A boundary whose mount table no receipt can hold is refused while it is
//! prepared, and the refusal is recorded (I01).
//!
//! The row count does not bound a table's bytes: a few hundred protected
//! `.git` directories under a long path of control characters (each one
//! escaped to six bytes in a receipt) make a table of several MiB well
//! inside the row bound, and a receipt holding it would be past the 4 MiB
//! every reader holds receipts to. The platform measures the table before
//! the supervisor records any of it (`platform::MOUNT_TABLE_BYTES_MAX`), so
//! the refused receipt carries no table and stays within its bound.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use ouro_fixture::harness::Jail;

mod common;

/// How many `.git` directories the workspace holds.
const REPOS: usize = 250;
/// One path component of control characters, at the 255-byte name limit's
/// side, and how many of them nest: about 3.5 KiB of path, under `PATH_MAX`.
const COMPONENT: usize = 250;
const DEPTH: usize = 14;

/// Plants the deep repositories.
fn plant(workspace: &Path) {
    let mut deep = workspace.to_path_buf();
    for _ in 0..DEPTH {
        deep.push("\u{1}".repeat(COMPONENT));
    }
    for index in 0..REPOS {
        let repo = deep.join(format!("r{index}"));
        std::fs::create_dir_all(repo.join(".git/hooks")).unwrap();
        std::fs::write(repo.join(".git/config"), b"").unwrap();
    }
}

/// The one attempt directory the run claimed.
fn only_attempt(data: &Path) -> PathBuf {
    let attempts: Vec<PathBuf> = std::fs::read_dir(data.join("attempts"))
        .expect("an attempt was claimed")
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(attempts.len(), 1, "{attempts:?}");
    attempts.into_iter().next().unwrap()
}

/// Attempted, live: a `tool` run over the planted workspace. Verdict:
/// refused as a configuration (exit 2, `invalid_config`) naming the
/// table's size and its bound, with a refused receipt on disk, within the
/// reader bound and carrying no mount table, and the target never ran.
#[test]
fn a_mount_table_past_its_bytes_is_refused_with_a_receipt() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    plant(&workspace);
    let marker = jail.root().join("target-ran");
    let data = jail.data_dir();
    let run = jail
        .arg("run")
        .arg("--profile")
        .arg("tool")
        .arg("--workspace")
        .arg(&workspace)
        .target([
            OsString::from("/usr/bin/touch"),
            marker.clone().into_os_string(),
        ])
        .run()
        .unwrap();
    let stderr = run.stderr_text();
    assert_eq!(run.code(), Some(2), "{stderr}");
    assert!(!marker.exists(), "the target ran");
    assert!(
        stderr.contains("invalid_config") && stderr.contains("bytes of a receipt"),
        "{stderr}"
    );
    assert!(!stderr.contains("not persisted"), "{stderr}");

    let receipt_path = only_attempt(&data).join("jail.json");
    let bytes = std::fs::read(&receipt_path).expect("the refusal is recorded");
    assert!(
        u64::try_from(bytes.len()).unwrap() <= ouro_jail::cleanup::RECEIPT_MAX,
        "{} bytes",
        bytes.len()
    );
    let receipt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(receipt["phase"], "refused", "{receipt:#}");
    assert_eq!(receipt["outcome"]["error"]["code"], "invalid_config");
    assert_eq!(
        receipt["applied"]["filesystem"],
        serde_json::Value::Null,
        "no mount table was recorded"
    );
}
