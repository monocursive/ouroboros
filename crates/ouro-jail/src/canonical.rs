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

/// Why a value cannot be canonicalized.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CanonicalError {
    /// RFC 8785 number canonicalization for floats is out of scope here.
    FloatNotSupported,
    /// A number outside the `i64`/`u64` range the snapshot admits.
    NumberOutOfRange(String),
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonicalError::FloatNotSupported => f.write_str(
                "canonical bytes do not cover floating-point numbers; no policy field is a float",
            ),
            CanonicalError::NumberOutOfRange(value) => {
                write!(f, "number {value} is outside the supported integer range")
            }
        }
    }
}

impl std::error::Error for CanonicalError {}

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

/// Encodes `value` as RFC 8785 canonical UTF-8, without BOM or trailing newline.
///
/// # Errors
/// Returns [`CanonicalError`] for a float or an out-of-range number.
pub fn to_jcs(value: &serde_json::Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => out.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => out.extend_from_slice(b"false"),
        serde_json::Value::Number(number) => {
            if let Some(signed) = number.as_i64() {
                out.extend_from_slice(signed.to_string().as_bytes());
            } else if let Some(unsigned) = number.as_u64() {
                out.extend_from_slice(unsigned.to_string().as_bytes());
            } else if number.is_f64() {
                return Err(CanonicalError::FloatNotSupported);
            } else {
                return Err(CanonicalError::NumberOutOfRange(number.to_string()));
            }
        }
        serde_json::Value::String(text) => write_string(text, out),
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        serde_json::Value::Object(members) => {
            // RFC 8785 §3.2.3: sort member names by their UTF-16 code units.
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by(|left, right| {
                let left: Vec<u16> = left.encode_utf16().collect();
                let right: Vec<u16> = right.encode_utf16().collect();
                left.cmp(&right)
            });
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                let member = members
                    .get(key.as_str())
                    .expect("key comes from this object's own key set");
                write_value(member, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// RFC 8785 §3.2.2.2 string serialization: the ECMAScript `JSON.stringify`
/// escape set, everything else as literal UTF-8.
fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            control if (control as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", control as u32).as_bytes());
            }
            other => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
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
