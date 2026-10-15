#![cfg(target_os = "linux")]
//! I01 for `none`: the uncontained profile inherits the operator's
//! environment, and its receipts list the name of every variable it
//! inherits (`applied.environment_names`) and of every reserved one it
//! strips (`removed_environment_names`). An environment whose names no
//! receipt could hold, more than the 1024 each list takes or names too
//! large for the bound every receipt is written within, is refused as a
//! configuration (exit 2) before any attempt is claimed, in `explain` as in
//! `run`; one at the bound runs and is recorded whole.
//!
//! The refusals need nothing of the host but the binary: they come before
//! any boundary. The run at the bound needs the delegated cgroup leaf every
//! `none` run does.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use ukai_fixture::harness::Jail;

mod common;

/// The names of this test's environment the jail it starts has, as the
/// launcher will have them (lossy past UTF-8, unique): the harness passes
/// it on and adds `UKAI_DATA_DIR` and `UKAI_CONFIG_DIR`. With `reserved`,
/// the `UKAI_*` names, which are stripped (removed); without, the others,
/// which are inherited.
fn names_here(reserved: bool) -> usize {
    let mut names: Vec<String> = std::env::vars_os()
        .map(|(name, _)| name)
        .filter(|name| name.as_bytes().starts_with(b"UKAI_") == reserved)
        .map(|name| String::from_utf8_lossy(name.as_bytes()).into_owned())
        .collect();
    if reserved {
        names.extend(["UKAI_DATA_DIR".to_owned(), "UKAI_CONFIG_DIR".to_owned()]);
    }
    names.sort();
    names.dedup();
    names.len()
}

/// A `none` run of `touch MARKER` over a private workspace, with `env`
/// added to what the jail inherits; and the marker.
fn none_run(env: &[(OsString, OsString)]) -> (Jail, PathBuf) {
    let mut jail = Jail::new().expect("a private harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).expect("the workspace");
    let marker = jail.root().join("target-ran");
    for (name, value) in env {
        jail = jail.env(name, value);
    }
    let jail = jail
        .arg("run")
        .arg("--profile")
        .arg("none")
        .arg("--workspace")
        .arg(&workspace)
        .target([
            OsString::from("/usr/bin/touch"),
            marker.clone().into_os_string(),
        ]);
    (jail, marker)
}

/// `count` variables named `PREFIX0`, `PREFIX1`, ...
fn padding(prefix: &str, count: usize) -> Vec<(OsString, OsString)> {
    (0..count)
        .map(|index| {
            (
                OsString::from(format!("{prefix}{index}")),
                OsString::from("v"),
            )
        })
        .collect()
}

/// No attempt was claimed under `data`.
fn assert_nothing_claimed(data: &Path) {
    let attempts = data.join("attempts");
    assert!(
        std::fs::read_dir(&attempts).map_or(true, |mut entries| entries.next().is_none()),
        "an attempt was claimed under {}",
        attempts.display()
    );
}

/// Runs `env` under `none` and checks it is refused before any claim, with
/// a message containing `says`, and that `explain` agrees.
fn assert_refused_before_the_claim(env: &[(OsString, OsString)], says: &str) {
    let (jail, marker) = none_run(env);
    let data = jail.data_dir();
    let run = jail.run().expect("the jail runs");
    let stderr = run.stderr_text();
    assert_eq!(run.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("invalid_config") && stderr.contains(says),
        "{stderr}"
    );
    assert!(!marker.exists(), "the target ran");
    assert_nothing_claimed(&data);

    let mut explain = Jail::new().expect("a private harness");
    let workspace = explain.root().join("workspace");
    std::fs::create_dir(&workspace).expect("the workspace");
    for (name, value) in env {
        explain = explain.env(name, value);
    }
    let explained = explain
        .arg("explain")
        .arg("--profile")
        .arg("none")
        .arg("--workspace")
        .arg(&workspace)
        .run()
        .expect("the jail runs");
    assert_eq!(explained.code(), Some(2), "{}", explained.stderr_text());
    assert!(
        explained.stderr_text().contains(says),
        "{}",
        explained.stderr_text()
    );
}

/// Attempted, live: a `none` run whose environment carries ten names of
/// 100000 control characters, each escaped to six bytes in a receipt (about
/// 6 MB of names, well under the 1024-name bound). Verdict: refused before
/// the claim, naming the variables and the bound, and the target never ran.
#[test]
fn an_environment_whose_names_are_too_large_is_refused_before_the_claim() {
    let env: Vec<(OsString, OsString)> = (0..10)
        .map(|index| {
            (
                OsString::from(format!("{}N{index}", "\u{1}".repeat(100_000))),
                OsString::from("v"),
            )
        })
        .collect();
    assert_refused_before_the_claim(&env, "cannot be recorded");
}

/// Attempted, live: a `none` run inheriting 1025 names, then one stripping
/// 1025 reserved ones. Verdict: each refused before the claim, naming the
/// list and the schema's bound, and the target never ran.
#[test]
fn an_environment_past_1024_names_is_refused_before_the_claim() {
    let inherited = names_here(false);
    assert!(
        inherited < 1024,
        "this test's own environment has {inherited} names"
    );
    assert_refused_before_the_claim(&padding("PAD_", 1025 - inherited), "1025 environment names");
    let removed = names_here(true);
    assert_refused_before_the_claim(
        &padding("UKAI_PAD_", 1025 - removed),
        "1025 removed environment names",
    );
}

/// Attempted, live: a `none` run inheriting exactly 1024 names. Verdict: it
/// runs, and its settled receipt lists all 1024, schema-valid.
#[test]
fn an_environment_of_1024_names_runs_and_is_recorded_whole() {
    if !common::delegated_leaf() {
        return;
    }
    let (jail, marker) = none_run(&padding("PAD_", 1024 - names_here(false)));
    let run = jail.receipt().run().expect("the jail runs");
    let stderr = run.stderr_text();
    assert_eq!(run.code(), Some(0), "{stderr}");
    assert!(marker.exists(), "the target did not run");
    let receipt = run
        .receipt_phase("settled")
        .unwrap_or_else(|| panic!("{stderr}"));
    common::check_receipt(&receipt).unwrap_or_else(|error| panic!("{error}"));
    let names = receipt["applied"]["environment_names"]
        .as_array()
        .expect("the names");
    assert_eq!(names.len(), 1024);
    assert!(names.iter().any(|name| name == "PAD_0"));
}
