//! Every schema identifier the ledger writes or accepts, in one place.
//!
//! `version --json` announces [`ANNOUNCED`]; a test binds each entry that
//! names a contract file to the identifier that file declares, and every
//! identifier a ledger contract declares to an entry here.

use ukai_records::records;

pub const RUN: &str = "ukai.ledger.run/1";
/// Every canonical record other than a flattened source event.
pub const RECORD: &str = "ukai.ledger.event/1";
pub const REQUEST: &str = "ukai.ledger.request/1";
pub const SEGMENTS: &str = "ukai.ledger.segments/2";
/// Read only, for stores written before multi-segment manifests.
pub const SEGMENTS_V1: &str = "ukai.ledger.segments/1";
pub const READ: &str = "ukai.ledger.read/1";
pub const EXPORT: &str = "ukai.ledger.export/1";
pub const TAIL: &str = "ukai.ledger.tail/1";
pub const QUERY: &str = "ukai.ledger.query/1";
pub const DIFF: &str = "ukai.ledger.diff/1";
pub const CATALOG: &str = "ukai.ledger.catalog/1";
pub const CATALOG_POSITION: &str = "ukai.ledger.catalog-position/1";
pub const DISCOVERY: &str = "ukai.ledger.discovery/1";
pub const DISCOVERY_POSITION: &str = "ukai.ledger.discovery-position/1";
pub const SHOW: &str = "ukai.ledger.show/1";
pub const TRANSCRIPT: &str = "ukai.ledger.transcript/1";
pub const BUNDLE: &str = "ukai.ledger.bundle/1";
pub const SIGNED_BUNDLE: &str = "ukai.ledger.bundle/2";
pub const BUNDLE_VERIFICATION: &str = "ukai.ledger.bundle-verification/1";
pub const SIGNED_BUNDLE_VERIFICATION: &str = "ukai.ledger.bundle-verification/2";
pub const BUNDLE_SIGNATURE: &str = "ukai.ledger.bundle-signature/1";
pub const SIGNER: &str = "ukai.ledger.signer/1";
pub const GC_PLAN: &str = "ukai.ledger.gc-plan/1";
pub const GC_RESULT: &str = "ukai.ledger.gc-result/1";
pub const GC_ANCHOR: &str = "ukai.ledger.gc-anchor/1";
pub const GC_COMPLETE: &str = "ukai.ledger.gc-complete/1";
pub const CAPTURE_GC_ANCHOR: &str = "ukai.ledger.capture-gc-anchor/1";
pub const CAPTURE_GC_COMPLETE: &str = "ukai.ledger.capture-gc-complete/1";
pub const REDACTION: &str = "ukai.ledger.redaction/1";
pub const DOCTOR: &str = "ukai.ledger.doctor/1";

// Private storage and process hand-off formats; never announced.
pub(crate) const READER_CHECKPOINT: &str = "ukai.ledger.reader-checkpoint/2";
pub(crate) const READER_CHECKPOINT_V1: &str = "ukai.ledger.reader-checkpoint/1";
pub(crate) const PENDING: &str = "ukai.ledger.pending/1";
// Detached ownership is Linux-only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const OWNER_LAUNCH: &str = "ukai.ledger.owner-launch/1";

/// One announced identifier and the contract file under `docs/specs` that
/// freezes it, if any.
pub struct Announced {
    pub key: &'static str,
    pub id: &'static str,
    pub contract: Option<&'static str>,
}

const fn frozen(key: &'static str, id: &'static str, contract: &'static str) -> Announced {
    Announced {
        key,
        id,
        contract: Some(contract),
    }
}

const fn open(key: &'static str, id: &'static str) -> Announced {
    Announced {
        key,
        id,
        contract: None,
    }
}

pub const ANNOUNCED: &[Announced] = &[
    frozen("run", RUN, "ledger-v1/run.schema.json"),
    frozen("event", records::SCHEMA_EVENT, "jail-v1/event.schema.json"),
    frozen(
        "receipt",
        records::SCHEMA_RECEIPT,
        "jail-v1/jail-receipt.schema.json",
    ),
    frozen("record", RECORD, "ledger-v1/record.schema.json"),
    frozen("request", REQUEST, "ledger-v1/request.schema.json"),
    frozen("segments", SEGMENTS, "ledger-v1/segments.schema.json"),
    frozen(
        "legacy_segments",
        SEGMENTS_V1,
        "ledger-v1/segments.schema.json",
    ),
    frozen("redaction", REDACTION, "ledger-v1/source.schema.json"),
    frozen("read", READ, "ledger-v1/read.schema.json"),
    frozen("export", EXPORT, "ledger-v1/export.schema.json"),
    frozen("tail", TAIL, "ledger-v1/tail.schema.json"),
    frozen("query", QUERY, "ledger-v1/query.schema.json"),
    frozen("diff", DIFF, "ledger-v1/diff.schema.json"),
    frozen("catalog", CATALOG, "ledger-v1/catalog.schema.json"),
    frozen("discovery", DISCOVERY, "ledger-v1/discovery.schema.json"),
    frozen("show", SHOW, "ledger-v1/show.schema.json"),
    frozen("transcript", TRANSCRIPT, "ledger-v1/show.schema.json"),
    frozen("bundle", BUNDLE, "ledger-v1/bundle.schema.json"),
    frozen(
        "bundle_verification",
        BUNDLE_VERIFICATION,
        "ledger-v1/bundle-verification.schema.json",
    ),
    frozen(
        "signed_bundle",
        SIGNED_BUNDLE,
        "ledger-v1/bundle-v2.schema.json",
    ),
    frozen(
        "signed_bundle_verification",
        SIGNED_BUNDLE_VERIFICATION,
        "ledger-v1/bundle-verification-v2.schema.json",
    ),
    frozen(
        "bundle_signature",
        BUNDLE_SIGNATURE,
        "ledger-v1/bundle-signature.schema.json",
    ),
    frozen("signer", SIGNER, "ledger-v1/signer.schema.json"),
    frozen("gc_plan", GC_PLAN, "ledger-v1/gc-plan.schema.json"),
    frozen("gc_result", GC_RESULT, "ledger-v1/gc-result.schema.json"),
    frozen("gc_anchor", GC_ANCHOR, "ledger-v1/gc-anchor.schema.json"),
    frozen(
        "gc_complete",
        GC_COMPLETE,
        "ledger-v1/gc-complete.schema.json",
    ),
    frozen(
        "capture_gc_anchor",
        CAPTURE_GC_ANCHOR,
        "ledger-v1/capture-gc-anchor.schema.json",
    ),
    frozen(
        "capture_gc_complete",
        CAPTURE_GC_COMPLETE,
        "ledger-v1/capture-gc-complete.schema.json",
    ),
    // Opaque continuation positions and the writer's readiness reply have no
    // contract file: they may change with the ledger version.
    open("catalog_position", CATALOG_POSITION),
    open("discovery_position", DISCOVERY_POSITION),
    open("doctor", DOCTOR),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, path::Path};

    fn specs() -> &'static Path {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/specs"))
    }

    fn declared(text: &str) -> BTreeSet<String> {
        text.split('"')
            .filter(|s| {
                s.starts_with("ukai.")
                    && s.rsplit_once('/').is_some_and(|(_, v)| {
                        !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())
                    })
            })
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn announced_identifiers_match_their_contracts_and_cover_every_ledger_schema() {
        let mut keys = BTreeSet::new();
        for entry in ANNOUNCED {
            assert!(keys.insert(entry.key), "duplicate key {}", entry.key);
            if let Some(contract) = entry.contract {
                let text = std::fs::read_to_string(specs().join(contract)).unwrap();
                assert!(
                    declared(&text).contains(entry.id),
                    "{contract} does not declare {}",
                    entry.id
                );
            }
        }
        let announced: BTreeSet<_> = ANNOUNCED.iter().map(|entry| entry.id).collect();
        let private = [
            READER_CHECKPOINT,
            READER_CHECKPOINT_V1,
            PENDING,
            OWNER_LAUNCH,
        ];
        for file in std::fs::read_dir(specs().join("ledger-v1")).unwrap() {
            let path = file.unwrap().path();
            if !path.to_string_lossy().ends_with(".schema.json") {
                continue;
            }
            for id in declared(&std::fs::read_to_string(&path).unwrap()) {
                assert!(
                    announced.contains(id.as_str()),
                    "{} declares {id}, which version does not announce",
                    path.display()
                );
                assert!(!private.contains(&id.as_str()));
            }
        }
    }
}
