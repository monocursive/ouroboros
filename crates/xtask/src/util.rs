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
