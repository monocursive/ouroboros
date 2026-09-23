//! Canonical bytes and digests.
//!
//! Implements `docs/specs/jail-v1/canonicalization.md`: RFC 8785 (JCS) encoding
//! of the policy snapshot, the `ouro.jail.policy/1` digest preimage and the
//! `ouro.jail.argv/1` length-prefixed argv preimage.
//!
//! The serializer covers exactly the value kinds a snapshot uses: null, bool,
//! integers inside `i64`/`u64`, strings, arrays and objects. A floating-point
//! number refuses with an internal error rather than guessing the ECMAScript
//! shortest-round-trip form that RFC 8785 §3.2.2.3 would require: no snapshot
//! field is a float, so a float here is a defect in the caller, and inventing
//! bytes for it would silently change a digest.

use sha2::{Digest as _, Sha256};

use crate::records::{ErrorCode, ErrorStage, JailError, Remediation, SCHEMA_POLICY};

mod jcs;

pub use jcs::{CanonicalError, to_jcs};

impl From<CanonicalError> for JailError {
    fn from(error: CanonicalError) -> Self {
        JailError::new(
            ErrorCode::InternalError,
            ErrorStage::Resolving,
            Remediation::InspectState,
            error.to_string(),
        )
    }
}

/// `"sha256:" || lowercase_hex(SHA256(bytes))`.
#[must_use]
pub fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The policy digest preimage: `ASCII("ouro.jail.policy/1") || 0x00 || J`.
///
/// # Errors
/// Returns [`CanonicalError`] when the snapshot value cannot be canonicalized.
pub fn policy_preimage(snapshot: &serde_json::Value) -> Result<Vec<u8>, CanonicalError> {
    let canonical = to_jcs(snapshot)?;
    let mut preimage = Vec::with_capacity(SCHEMA_POLICY.len() + 1 + canonical.len());
    preimage.extend_from_slice(SCHEMA_POLICY.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&canonical);
    Ok(preimage)
}

/// `policy_digest` of a snapshot value (canonicalization.md §"Hash algorithms").
///
/// # Errors
/// Returns [`CanonicalError`] when the snapshot value cannot be canonicalized.
pub fn policy_digest(snapshot: &serde_json::Value) -> Result<String, CanonicalError> {
    Ok(sha256_prefixed(&policy_preimage(snapshot)?))
}

/// The argv preimage of canonicalization.md §"Hash algorithms".
///
/// `ASCII("ouro.jail.argv/1") || 0x00 || U64BE(argc)` then, per argument,
/// `U64BE(len) || bytes`. Lengths count native bytes. Every literal argument is
/// hashed, including `PROGRAM` before PATH lookup.
#[must_use]
pub fn argv_preimage(argv: &[Vec<u8>]) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"ouro.jail.argv/1");
    preimage.push(0);
    preimage.extend_from_slice(&(argv.len() as u64).to_be_bytes());
    for argument in argv {
        preimage.extend_from_slice(&(argument.len() as u64).to_be_bytes());
        preimage.extend_from_slice(argument);
    }
    preimage
}

/// `argv_digest` of the literal operator argv.
#[must_use]
pub fn argv_digest(argv: &[Vec<u8>]) -> String {
    sha256_prefixed(&argv_preimage(argv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_object_keys_by_utf16_code_units() {
        // U+FF3A (fullwidth Z) is one UTF-16 unit; U+1F600 is a surrogate pair
        // whose first unit (0xD83D) sorts before 0xFF3A even though its code
        // point is larger. Sorting by chars would order these the other way.
        let value = serde_json::json!({ "\u{ff3a}": 1, "\u{1f600}": 2 });
        let canonical = to_jcs(&value).expect("canonicalizable");
        let text = String::from_utf8(canonical).expect("utf-8");
        assert!(
            text.starts_with("{\"\u{1f600}\""),
            "surrogate pair must sort first, got {text}"
        );
    }

    #[test]
    fn escapes_the_ecmascript_set_and_leaves_other_characters_literal() {
        let value = serde_json::json!("a\"b\\c\u{08}\u{0c}\n\r\t\u{01}é");
        let canonical = to_jcs(&value).expect("canonicalizable");
        assert_eq!(
            String::from_utf8(canonical).expect("utf-8"),
            "\"a\\\"b\\\\c\\b\\f\\n\\r\\t\\u0001é\""
        );
    }

    #[test]
    fn refuses_floats_rather_than_inventing_a_number_form() {
        let value = serde_json::json!({ "wall": 1.5 });
        assert_eq!(to_jcs(&value), Err(CanonicalError::FloatNotSupported));
    }

    #[test]
    fn argv_framing_is_length_prefixed_not_delimited() {
        assert_ne!(
            argv_digest(&[b"ab".to_vec(), b"c".to_vec()]),
            argv_digest(&[b"a".to_vec(), b"bc".to_vec()])
        );
        assert_ne!(argv_digest(&[]), argv_digest(&[Vec::new()]));
    }
}
