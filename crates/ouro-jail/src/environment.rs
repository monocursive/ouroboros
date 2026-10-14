//! Reserved environment names.
//!
//! jail-v1 §12: "`none` inherits the host environment except reserved
//! Ouroboros state, socket and token names; the receipt lists removed names,
//! never values. This is hygiene and does not protect uncontained state."
//!
//! The reserved set is every `OURO_*` name: the operator settings of §6.2
//! ([`crate::config::ENVIRONMENT_ALLOW_LIST`]) and every state, socket, token
//! or control variable an Ouroboros component defines under the same prefix
//! (the vault's `OURO_VAULT_*` placeholders among them). Neither the
//! specification nor the schemas name a reserved variable outside that
//! prefix. The match is on bytes and case-sensitive: stripping removes the
//! operator's own variables from an uncontained child, and `ouro_x` is an
//! ordinary name of theirs to keep.
//!
//! A launch profile's `environment` table is validated more strictly
//! ([`crate::launch_profile::reserved_reason`]): it refuses every name this
//! predicate reserves in any letter case, so a name the jail reserves can
//! neither leak into an uncontained child nor be written into a contained
//! one.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;

/// The prefix every reserved name starts with.
pub const RESERVED_PREFIX: &[u8] = b"OURO_";

/// True for names the jail reserves: every `OURO_*` name (state, socket,
/// token and control variables), matched byte-exactly and case-sensitively.
#[must_use]
pub fn is_reserved(name: &OsStr) -> bool {
    name.as_bytes().starts_with(RESERVED_PREFIX)
}

/// Splits an inherited environment into (kept, removed names sorted).
///
/// Order and bytes of the kept pairs are preserved. The removed list carries
/// names only, never a value (I09), sorted and without duplicates. A removed
/// name that is not UTF-8 is rendered lossily: the receipt's name lists are
/// JSON strings, which is how `environment_names` renders such a name too.
/// Only the `none` boundary, which inherits the host environment, strips it.
pub fn strip_reserved(
    env: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> (Vec<(std::ffi::OsString, std::ffi::OsString)>, Vec<String>) {
    let mut kept = Vec::new();
    let mut removed = Vec::new();
    for (name, value) in env {
        if is_reserved(&name) {
            removed.push(String::from_utf8_lossy(name.as_bytes()).into_owned());
        } else {
            kept.push((name, value));
        }
    }
    removed.sort();
    removed.dedup();
    (kept, removed)
}

/// The names a launcher started with `host` (stripped of every reserved
/// name, [`strip_reserved`]) and the `bound` names has, as the platform
/// reads them back from it: sorted, without duplicates, a name that is not
/// UTF-8 rendered lossily; and the reserved names stripped. What the
/// receipts of a run that inherits `host` list (`environment_names`,
/// `removed_environment_names`), known before anything is claimed.
pub fn inherited_names<'a>(
    host: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    bound: impl IntoIterator<Item = &'a str>,
) -> (Vec<String>, Vec<String>) {
    let (kept, removed) = strip_reserved(host);
    let mut names: Vec<String> = kept
        .iter()
        .map(|(name, _)| String::from_utf8_lossy(name.as_bytes()).into_owned())
        .chain(bound.into_iter().map(str::to_owned))
        .collect();
    names.sort();
    names.dedup();
    (names, removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    fn os(text: &str) -> OsString {
        OsString::from(text)
    }

    #[test]
    fn every_ouro_name_is_reserved_and_nothing_else_is() {
        for name in [
            "OURO_",
            "OURO_DATA_DIR",
            "OURO_CONFIG_DIR",
            "OURO_JAIL_OBSERVE",
            "OURO_JAIL_EVIDENCE",
            "OURO_ANYTHING_ELSE",
        ] {
            assert!(is_reserved(OsStr::new(name)), "{name}");
        }
        for name in [
            "OURO",
            "ouro_data_dir",
            "Ouro_DATA_DIR",
            "XOURO_",
            "_OURO_",
            "PATH",
            "",
            " OURO_",
        ] {
            assert!(!is_reserved(OsStr::new(name)), "{name:?}");
        }
    }

    /// The names an inheriting run's receipts list are the ones its
    /// launcher has: kept and bound, sorted and unique, lossy past UTF-8;
    /// the reserved ones are listed apart, never with a value.
    #[test]
    fn inherited_names_are_the_launchers_names() {
        let env = vec![
            (os("PATH"), os("/usr/bin")),
            (os("OURO_TOKEN"), os("secret")),
            (OsString::from_vec(b"BYTES\xff".to_vec()), os("x")),
            (os("HOME"), os("/home")),
        ];
        let (names, removed) = inherited_names(env, ["TERM", "HOME"]);
        assert_eq!(names, ["BYTES\u{fffd}", "HOME", "PATH", "TERM"]);
        assert_eq!(removed, ["OURO_TOKEN"]);
    }

    #[test]
    fn a_non_utf8_suffix_is_still_reserved() {
        let name = OsString::from_vec(b"OURO_\xff\xfe".to_vec());
        assert!(is_reserved(&name));
        let (kept, removed) = strip_reserved([(name, os("v"))]);
        assert!(kept.is_empty());
        assert_eq!(removed.len(), 1);
        assert!(removed[0].starts_with("OURO_"));
    }

    #[test]
    fn stripping_keeps_order_and_bytes_and_reports_sorted_names_only() {
        let secret = "value-that-must-never-be-listed";
        let env = vec![
            (os("PATH"), os("/usr/bin")),
            (os("OURO_TOKEN"), os(secret)),
            (os("ouro_lower"), os("kept")),
            (os("OURO_DATA_DIR"), os("/state")),
            (OsString::from_vec(b"BYTES\xff".to_vec()), os("x")),
            (os("OURO_TOKEN"), os("duplicate")),
        ];
        let (kept, removed) = strip_reserved(env);
        let kept_names: Vec<&[u8]> = kept.iter().map(|(name, _)| name.as_bytes()).collect();
        assert_eq!(
            kept_names,
            vec![&b"PATH"[..], &b"ouro_lower"[..], &b"BYTES\xff"[..]]
        );
        assert_eq!(removed, vec!["OURO_DATA_DIR", "OURO_TOKEN"]);
        assert!(removed.iter().all(|name| !name.contains(secret)));
    }
}
