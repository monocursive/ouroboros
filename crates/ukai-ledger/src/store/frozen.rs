//! Validation against the frozen jail and ledger schemas.
use std::{collections::BTreeMap, sync::OnceLock};

use serde_json::Value;
use ukai_records::records;

use crate::protocol::{LedgerError, Result};

pub(super) fn validate_frozen(name: &str, value: &Value) -> Result<()> {
    static VALIDATORS: OnceLock<BTreeMap<&'static str, jsonschema::Validator>> = OnceLock::new();
    let validators = VALIDATORS.get_or_init(|| {
        let schemas = [
            (
                "event",
                include_str!("../../../../docs/specs/jail-v1/event.schema.json"),
            ),
            (
                "jail-event",
                include_str!("../../../../docs/specs/jail-v1/jail-event.schema.json"),
            ),
            (
                "jail-receipt",
                include_str!("../../../../docs/specs/jail-v1/jail-receipt.schema.json"),
            ),
            (
                "request",
                include_str!("../../../../docs/specs/ledger-v1/request.schema.json"),
            ),
            (
                "source",
                include_str!("../../../../docs/specs/ledger-v1/source.schema.json"),
            ),
            (
                "record",
                include_str!("../../../../docs/specs/ledger-v1/record.schema.json"),
            ),
            (
                "run",
                include_str!("../../../../docs/specs/ledger-v1/run.schema.json"),
            ),
        ]
        .map(|(name, source)| {
            (
                name,
                serde_json::from_str::<Value>(source).expect("checked-in frozen schema"),
            )
        });
        let resources = schemas.iter().map(|(_, schema)| {
            (
                schema["$id"].as_str().expect("frozen schema id").to_owned(),
                jsonschema::Resource::from_contents(schema.clone()),
            )
        });
        let registry: &'static jsonschema::Registry = Box::leak(Box::new(
            jsonschema::Registry::new()
                .extend(resources)
                .expect("frozen schema registry")
                .prepare()
                .expect("prepared frozen registry"),
        ));
        schemas
            .into_iter()
            .map(|(name, schema)| {
                (
                    name,
                    jsonschema::options()
                        .with_registry(registry)
                        .should_validate_formats(true)
                        .build(&schema)
                        .expect("frozen schema validator"),
                )
            })
            .collect()
    });
    if validators[name].is_valid(value) {
        Ok(())
    } else {
        Err(LedgerError::refused(format!(
            "record violates frozen {name} schema"
        )))
    }
}

pub(super) fn validate_receipt(receipt: &Value) -> Result<()> {
    validate_frozen("jail-receipt", receipt)?;
    if !records::semantic::receipt(receipt).is_empty() {
        return Err(LedgerError::refused(
            "record violates jail receipt semantics",
        ));
    }
    Ok(())
}

pub(crate) fn validate_source(event: &Value, attempt_id: &str) -> Result<records::Event> {
    validate_frozen("jail-event", event)?;
    let typed: records::Event = serde_json::from_value(event.clone())?;
    if typed.attempt_id != attempt_id || !records::semantic::event(event).is_empty() {
        return Err(LedgerError::refused(
            "source attempt or semantic contract mismatch",
        ));
    }
    Ok(typed)
}

/// The frozen request schema states the whole plan, and the run projection
/// embeds it by reference: any hand-written copy that drifted from it could
/// acknowledge a preparation whose projection then refuses at every start.
pub(crate) fn validate_payload(payload: &Value) -> Result<()> {
    validate_frozen("request", payload).map_err(|_| {
        LedgerError::refused("prepare only accepts the versioned digest-only request plan")
    })?;
    // JSON Schema's integer also admits 1.0; the limit is a byte count.
    if !payload["capture"]["limit_bytes"].is_u64() {
        return Err(LedgerError::refused(
            "capture limit must be a whole number of bytes",
        ));
    }
    Ok(())
}
