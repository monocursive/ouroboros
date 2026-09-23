//! Reserved environment names.
//!
//! jail-v1 §12: "`none` inherits the host environment except reserved
//! Ouroboros state, socket and token names; the receipt lists removed names,
//! never values. This is hygiene and does not protect uncontained state."
//! The same predicate is what a launch profile's `environment` table is
//! validated against, so a name the jail reserves can neither leak into an
//! uncontained child nor be written back into a contained one.
//!
//! The reserved set is every `OURO_*` name: the operator settings of §6.2
//! (`OURO_CONFIG_DIR`, `OURO_DATA_DIR`, `OURO_JAIL_OBSERVE`,
//! `OURO_JAIL_EVIDENCE`) and every state, socket, token or control variable a
//! later Ouroboros component defines under the same prefix. Neither the
//! specification nor the schemas name a reserved variable outside that
//! prefix. The match is on bytes and case-sensitive: `ouro_x` is an ordinary
//! name.

use std::ffi::{OsStr, OsString};
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
pub fn strip_reserved(
    env: impl IntoIterator<Item = (OsString, OsString)>,
) -> (Vec<(OsString, OsString)>, Vec<String>) {
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

#[cfg(test)]
mod tests {
    use super::*;
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
