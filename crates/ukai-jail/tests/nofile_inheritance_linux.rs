#![cfg(target_os = "linux")]
//! The target keeps the operator's descriptor limit.
//!
//! A contained run binds every protected segment from a pinned descriptor,
//! so a workspace with many of them needs more descriptors than a 1024 soft
//! limit allows: the supervisor raises its own soft `RLIMIT_NOFILE` to the
//! hard limit, and bubblewrap and the launcher inherit the raise because
//! bubblewrap must receive descriptors above it. The target must not: the
//! launcher sets the operator's soft limit back before the exec, so what the
//! target can open does not depend on how many protected segments the
//! workspace holds.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use ukai_fixture::harness::{self, Jail};

mod common;

/// The soft limit every run here starts from: the usual default.
const OPERATOR_SOFT: libc::rlim_t = 1024;
/// Enough `.git` segments that pinning them needs more than
/// [`OPERATOR_SOFT`] descriptors, and few enough for one receipt's mount
/// table.
const MANY_SEGMENTS: usize = 900;

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// The soft `Max open files` the target of a `tool` run over a workspace
/// with `segments` protected `.git` directories reads from its own
/// `/proc/self/limits`.
fn target_soft_limit(segments: usize) -> String {
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    private_dir(&workspace);
    for index in 0..segments {
        private_dir(&workspace.join(format!("r{index}/.git")));
    }
    let marker = workspace.join("limits");
    let _soft = common::SoftNofile::set(OPERATOR_SOFT);
    let run = jail
        .arg("run")
        .arg("--profile")
        .arg("tool")
        .arg("--workspace")
        .arg(&workspace)
        .receipt()
        .target([
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(format!(
                "grep 'Max open files' /proc/self/limits > {}",
                marker.display()
            )),
        ])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let line = std::fs::read_to_string(&marker).unwrap();
    // `Max open files  <soft>  <hard>  files`
    line.split_whitespace()
        .nth(3)
        .unwrap_or_else(|| panic!("no soft limit in {line:?}"))
        .to_owned()
}

/// Attempted, live: a workspace with no protected segment and one whose
/// segments need the raise. Verdict: the target reads the operator's soft
/// limit in both.
#[test]
fn the_target_keeps_the_operators_descriptor_limit() {
    if !common::live() {
        return;
    }
    if common::SoftNofile::read().rlim_max < 4 * OPERATOR_SOFT {
        harness::skip_or_fail(
            "the hard RLIMIT_NOFILE leaves no room for the supervisor to raise its soft one",
        );
        return;
    }
    let operator = OPERATOR_SOFT.to_string();
    assert_eq!(target_soft_limit(0), operator, "no protected segment");
    assert_eq!(
        target_soft_limit(MANY_SEGMENTS),
        operator,
        "{MANY_SEGMENTS} protected segments, which need the raise"
    );
}
