// TEMPORARY J3 scaffold, replaced at integration.
//
// The `none` slice (agent N) owns this file and its real implementation
// (J3 contract §3.1). The launch slice codes against the two signatures the
// contract fixes and ships this minimal body only so that its worktree builds;
// the integrator keeps N's file and drops this one.

//! Reserved environment names (jail-v1 §12).

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;

/// True for names the jail reserves: every `OURO_*` name (state, socket,
/// token and control variables), matched byte-exactly and case-sensitively.
#[must_use]
pub fn is_reserved(name: &OsStr) -> bool {
    name.as_bytes().starts_with(b"OURO_")
}

/// Splits an inherited environment into (kept, removed names sorted).
#[must_use]
pub fn strip_reserved(
    env: impl IntoIterator<Item = (OsString, OsString)>,
) -> (Vec<(OsString, OsString)>, Vec<String>) {
    let mut kept = Vec::new();
    let mut removed = Vec::new();
    for (name, value) in env {
        if is_reserved(&name) {
            removed.push(name.to_string_lossy().into_owned());
        } else {
            kept.push((name, value));
        }
    }
    removed.sort();
    removed.dedup();
    (kept, removed)
}
