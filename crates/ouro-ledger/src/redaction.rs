//! Explicit minimization at both durable ingress points: writer and owner journal.
//! This is a ledger transformation, never a claim about the original jail bytes.
use crate::protocol::{LedgerError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const SCHEMA: &str = "ouro.ledger.redaction/1";
const REASON: &str = "ledger_redacted";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Mark {
    schema: String,
    fields: Vec<String>,
}

pub(crate) fn validate_policy(payload: &Value) -> Result<()> {
    let Some(value) = payload.get("redact") else {
        return Ok(());
    };
    let Some(items) = value.as_array() else {
        return Err(invalid());
    };
    if items.is_empty()
        || items.len() > 2
        || items
            .iter()
            .any(|v| !matches!(v.as_str(), Some("paths" | "destinations")))
        || items.windows(2).any(|w| w[0].as_str() >= w[1].as_str())
    {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> LedgerError {
    LedgerError("invalid structured redaction policy or marker".into())
}

fn selected(payload: &Value, name: &str) -> bool {
    payload["redact"]
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v == name))
}

/// Remove only the ledger-owned marker before validating the frozen envelope.
pub(crate) fn envelope(event: &Value) -> Value {
    let mut source = event.clone();
    if let Some(object) = source.as_object_mut() {
        object.remove("redaction");
    }
    source
}

/// Validate before minimizing, so redaction cannot launder forbidden metadata.
/// Idempotent for transport retries and pending-journal reconciliation.
pub(crate) fn minimize(event: &Value, payload: &Value, attempt: &str) -> Result<Value> {
    validate_policy(payload)?;
    let mut source = envelope(event);
    crate::store::validate_source(&source, attempt)?;
    let allowed = |field: &str| match field {
        "path" | "path2" => selected(payload, "paths") && source["source"] == "audit",
        "destination" | "connected_address" | "origin" => {
            selected(payload, "destinations") && source["source"] == "proxy"
        }
        _ => false,
    };
    let mut marked = BTreeSet::new();
    if let Some(value) = event.get("redaction") {
        let mark: Mark = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        if mark.schema != SCHEMA
            || mark.fields.is_empty()
            || mark.fields.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(invalid());
        }
        for key in mark.fields {
            let expected = if key == "path" || key == "path2" {
                json!({"kind":"unavailable","reason":REASON})
            } else {
                Value::Null
            };
            if !allowed(&key) || source["fields"].get(&key) != Some(&expected) {
                return Err(invalid());
            }
            marked.insert(key);
        }
    }
    for key in [
        "path",
        "path2",
        "destination",
        "connected_address",
        "origin",
    ] {
        let Some(value) = source["fields"].get(key) else {
            continue;
        };
        let path = key == "path" || key == "path2";
        // The reserved reason always needs explicit ledger provenance, even if
        // an input bypasses the normal owner or has no selected policy.
        if path && value["reason"] == REASON && !marked.contains(key) {
            return Err(invalid());
        }
        if !allowed(key) || value.is_null() || path && value["kind"] == "unavailable" {
            continue;
        }
        marked.insert(key.to_owned());
    }
    for key in &marked {
        source["fields"][key] = if key == "path" || key == "path2" {
            json!({"kind":"unavailable","reason":REASON})
        } else {
            Value::Null
        };
    }
    if !marked.is_empty() {
        source["redaction"] = serde_json::to_value(Mark {
            schema: SCHEMA.into(),
            fields: marked.into_iter().collect(),
        })?;
    }
    Ok(source)
}

/// Recovery must reject unminimized canonical bytes, never rewrite history.
pub(crate) fn validate_stored(event: &Value, payload: &Value, attempt: &str) -> Result<()> {
    if minimize(event, payload, attempt)? != *event {
        return Err(LedgerError(
            "stored source violates immutable redaction policy".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
