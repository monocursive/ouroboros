//! Small helpers the tasks share.

use serde::Serialize;
use serde_json::Value;

/// The wire spelling of a unit value of a record's vocabulary (its serde
/// name), so facts compare against the records' own types.
///
/// # Panics
/// If `value` does not serialize to a JSON string, which only a type that
/// is not a unit enum does.
pub fn wire<T: Serialize>(value: T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        other => unreachable!("not a unit enum value: {other:?}"),
    }
}

/// Lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// [`sha256_hex`] of a file's bytes.
///
/// # Errors
/// The file cannot be read.
pub fn sha256_file(path: &std::path::Path) -> Result<String, String> {
    std::fs::read(path)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// A TOML basic string. JSON's escapes (`\"`, `\\`, `\n`, `\uXXXX`) are all
/// valid in a TOML basic string.
#[must_use]
pub fn toml_string(text: &str) -> String {
    serde_json::Value::String(text.to_owned()).to_string()
}
