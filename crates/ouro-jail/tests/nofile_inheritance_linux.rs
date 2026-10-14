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

use ouro_fixture::harness::{self, Jail};

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

/// This process's `RLIMIT_NOFILE`, lowered for the test and put back after.
struct SoftNofile(libc::rlimit);

impl SoftNofile {
    fn read() -> libc::rlimit {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a live, writable rlimit.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) },
            0
        );
        limit
    }

    fn set(soft: libc::rlim_t) -> SoftNofile {
        let old = SoftNofile::read();
        let lowered = libc::rlimit {
            rlim_cur: soft.min(old.rlim_max),
            rlim_max: old.rlim_max,
        };
        // SAFETY: a live rlimit; lowering the soft limit within the hard one.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lowered) },
            0
        );
        SoftNofile(old)
    }
}

impl Drop for SoftNofile {
    fn drop(&mut self) {
        // SAFETY: restores the rlimit read before the test lowered it.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const self.0) };
    }
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
    let _soft = SoftNofile::set(OPERATOR_SOFT);
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
    if SoftNofile::read().rlim_max < 4 * OPERATOR_SOFT {
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
