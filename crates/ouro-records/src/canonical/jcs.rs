//! RFC 8785 (JCS) canonical bytes for the JSON values jail records use.
//!
//! Depends on nothing but `std` and `serde_json`, so the conformance harness
//! (`ouro-fixture`, which does not depend on `ouro-jail`) includes this file
//! by path and cannot disagree with the product about canonical bytes.
//!
//! The serializer covers exactly the value kinds a policy snapshot or a
//! receipt uses: null, bool, integers inside `i64`/`u64`, strings, arrays and
//! objects. A floating-point number refuses rather than guessing the
//! ECMAScript shortest-round-trip form RFC 8785 §3.2.2.3 would require.

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
