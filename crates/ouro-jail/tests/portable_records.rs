//! R01 (portable part): the record types against the checked-in contract.
//!
//! Every example and receipt fixture deserializes into the Rust types and
//! re-serializes to an equal JSON value, so the types are not a lossy subset of
//! the schema. Every case in `fixtures/validation-cases.json` gets the verdict
//! the corpus expects from the schema itself. M02 is the hypothetical macOS
//! receipt: it validates with native macOS details and without Linux fields.
//!
//! The §13.2 phase tuples are built here from one [`AttemptRecord`] and
//! validated against the same schema, so a receipt this runtime emits is held
//! to the contract rather than to a hand-written expectation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonschema::{Registry, Resource, Validator};

mod common;
use ouro_jail::observer::CoverageSummary;
use ouro_jail::records::{
    Applied, AppliedFilesystem, AppliedLimit, AppliedMount, AppliedNetwork, AppliedSyscalls,
    AttemptRecord, ChildProtection, Containment, ErrorCode, ErrorStage, Event, EvidenceMode,
    JailError, JailRecord, Lifetime, NativeLifetime, NativeString, ObserveMode, Os, Outcome,
    OutcomeKind, Phase, PlatformRecord, PolicyRecord, ProcessIdentity, ProcessRecord, Receipt,
    Remediation, SCHEMA_RECEIPT, StateCleanup, rfc3339_utc, rfc3339_utc_from_unix,
};

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs/jail-v1")
        .canonicalize()
        .expect("the checked-in specification directory exists")
}

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()))
}

/// Builds one validator per checked-in schema, with the four registered by
/// `$id` so that `jail-event.schema.json` can `$ref` the shared envelope.
fn validators() -> BTreeMap<String, Validator> {
    let mut schemas: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for entry in std::fs::read_dir(specs_dir()).expect("the specification directory is readable") {
        let path = entry.expect("a directory entry").path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if let Some(stem) = name.strip_suffix(".schema.json") {
            schemas.insert(stem.to_owned(), read_json(&path));
        }
    }
    assert_eq!(schemas.len(), 4, "four schemas accompany the specification");

    let pairs: Vec<(String, Resource)> = schemas
        .values()
        .map(|schema| {
            let id = schema["$id"]
                .as_str()
                .expect("every schema declares an $id")
                .to_owned();
            (id, Resource::from_contents(schema.clone()))
        })
        .collect();
    let registry: Registry = Registry::new()
        .extend(pairs)
        .expect("the schema identifiers are valid URIs")
        .prepare()
        .expect("the registry resolves");
    let registry: &'static Registry = Box::leak(Box::new(registry));

    schemas
        .into_iter()
        .map(|(name, schema)| {
            let validator = jsonschema::options()
                .with_registry(registry)
                .should_validate_formats(true)
                .build(&schema)
                .unwrap_or_else(|error| panic!("compiling {name}: {error}"));
            (name, validator)
        })
        .collect()
}

fn index_of(segment: &serde_json::Value) -> usize {
    usize::try_from(segment.as_u64().expect("an array index is a number"))
        .expect("an in-range index")
}

fn step<'a>(
    cursor: &'a mut serde_json::Value,
    segment: &serde_json::Value,
) -> &'a mut serde_json::Value {
    match cursor {
        serde_json::Value::Array(items) => {
            items.get_mut(index_of(segment)).expect("the index exists")
        }
        other => other
            .get_mut(segment.as_str().expect("an object key"))
            .expect("the key exists"),
    }
}

fn errors(validator: &Validator, value: &serde_json::Value) -> Vec<String> {
    validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect()
}

fn record_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(specs_dir().join("examples"))
        .expect("the examples directory is readable")
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.push(specs_dir().join("fixtures/receipt-macos-hypothetical.json"));
    files.sort();
    files
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

#[test]
fn r01_every_example_round_trips_through_the_rust_types() {
    let files = record_files();
    assert!(files.len() >= 12, "the corpus is present: {files:?}");
    for path in files {
        let original = read_json(&path);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a file name");
        let produced = if name.starts_with("event-") {
            let event: Event = serde_json::from_value(original.clone())
                .unwrap_or_else(|error| panic!("{name} does not fit `Event`: {error}"));
            serde_json::to_value(&event).expect("an event serializes")
        } else {
            let receipt: Receipt = serde_json::from_value(original.clone())
                .unwrap_or_else(|error| panic!("{name} does not fit `Receipt`: {error}"));
            serde_json::to_value(&receipt).expect("a receipt serializes")
        };
        assert_eq!(produced, original, "{name} did not round-trip unchanged");
    }
}

#[test]
fn r01_every_example_validates_against_its_schema() {
    let validators = validators();
    for path in record_files() {
        let record = read_json(&path);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a file name");
        let key = if name.starts_with("event-") {
            "jail-event"
        } else {
            "jail-receipt"
        };
        let failures = errors(&validators[key], &record);
        assert!(failures.is_empty(), "{name}: {failures:?}");
        // J4-R, R01: the rules the schema cannot state, as validate_contract.py
        // checks them.
        if key == "jail-receipt" {
            common::semantic_receipt(&record)
                .unwrap_or_else(|error| panic!("{name} fails the semantic checks: {error}"));
        }
    }
}

// ---------------------------------------------------------------------------
// The validation-case corpus
// ---------------------------------------------------------------------------

#[test]
fn r01_every_validation_case_gets_the_verdict_the_corpus_expects() {
    let validators = validators();
    let cases = read_json(&specs_dir().join("fixtures/validation-cases.json"));
    let cases = cases.as_array().expect("the corpus is an array");
    assert!(cases.len() >= 44, "the corpus is present");
    let mut positive = 0usize;
    let mut negative = 0usize;
    for case in cases {
        let name = case["name"].as_str().expect("a case name");
        let schema = case["schema"].as_str().expect("a schema name");
        let mut record = read_json(&specs_dir().join(case["base"].as_str().expect("a base")));
        for change in case["changes"].as_array().expect("changes") {
            // A path segment is an object key or an array index, and the final
            // segment may name a key that does not exist yet, exactly as
            // `validate_contract.py` assigns it.
            let path = change["path"].as_array().expect("a path");
            let (last, parents) = path.split_last().expect("a non-empty path");
            let mut cursor = &mut record;
            for segment in parents {
                cursor = step(cursor, segment);
            }
            match cursor {
                serde_json::Value::Array(items) => {
                    let position = index_of(last);
                    items[position] = change["value"].clone();
                }
                other => {
                    other[last.as_str().expect("an object key")] = change["value"].clone();
                }
            }
        }
        let expected_valid = case["valid"].as_bool().expect("a verdict");
        let failures = errors(&validators[schema], &record);
        assert_eq!(
            failures.is_empty(),
            expected_valid,
            "case `{name}` expected valid={expected_valid}, errors: {failures:?}"
        );
        // J4-R, R01: as validate_contract.py does, a receipt the schema
        // accepts also passes the semantic checks.
        if failures.is_empty() && schema == "jail-receipt" {
            common::semantic_receipt(&record)
                .unwrap_or_else(|error| panic!("case `{name}` fails the semantic checks: {error}"));
        }
        if expected_valid {
            positive += 1;
        } else {
            negative += 1;
        }
    }
    assert!(
        positive > 0 && negative > 0,
        "the corpus tests both verdicts"
    );
}

#[test]
fn m02_the_hypothetical_macos_receipt_validates_without_linux_fields() {
    let validators = validators();
    let record = read_json(&specs_dir().join("fixtures/receipt-macos-hypothetical.json"));
    assert!(errors(&validators["jail-receipt"], &record).is_empty());
    assert_eq!(record["platform"]["os"], serde_json::json!("macos"));
    assert_eq!(
        record["lifetime"]["native"]["os"],
        serde_json::json!("macos")
    );
    assert_eq!(
        record["lifetime"]["boundary"],
        serde_json::json!("native_tree"),
        "a macOS boundary is never a Linux pid namespace"
    );
    let text = serde_json::to_string(&record).expect("serializes");
    for linux_only in ["pid_namespace", "cgroup", "pidfd", "boot_id", "/proc"] {
        assert!(
            !text.contains(linux_only),
            "the portable record carries no `{linux_only}`"
        );
    }
    // And the same record with a Linux boundary is rejected, so the check above
    // is not vacuous.
    let mut linux = record.clone();
    linux["lifetime"]["boundary"] = serde_json::json!("pid_namespace");
    assert!(!errors(&validators["jail-receipt"], &linux).is_empty());
}

// ---------------------------------------------------------------------------
// RFC 3339
// ---------------------------------------------------------------------------

#[test]
fn rfc3339_matches_known_epoch_values() {
    for (seconds, expected) in [
        (0i64, "1970-01-01T00:00:00Z"),
        (1, "1970-01-01T00:00:01Z"),
        (951_782_400, "2000-02-29T00:00:00Z"),
        (951_868_799, "2000-02-29T23:59:59Z"),
        (1_700_000_000, "2023-11-14T22:13:20Z"),
        (4_102_444_800, "2100-01-01T00:00:00Z"),
        (4_107_542_400, "2100-03-01T00:00:00Z"),
        (-1, "1969-12-31T23:59:59Z"),
        (-86_400, "1969-12-31T00:00:00Z"),
    ] {
        assert_eq!(
            rfc3339_utc_from_unix(seconds),
            expected,
            "unix {seconds} formats wrong"
        );
    }
    assert_eq!(
        rfc3339_utc(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
        "2023-11-14T22:13:20Z"
    );
    assert_eq!(
        rfc3339_utc(UNIX_EPOCH - Duration::from_secs(86_400)),
        "1969-12-31T00:00:00Z"
    );
}

#[test]
fn rfc3339_output_satisfies_the_schema_date_time_format() {
    let validators = validators();
    let mut record = read_json(&specs_dir().join("examples/receipt-macos-refused.json"));
    let stamp = rfc3339_utc(UNIX_EPOCH + Duration::from_secs(951_782_400));
    record["created_at"] = serde_json::json!(stamp);
    record["updated_at"] = serde_json::json!(stamp);
    assert!(errors(&validators["jail-receipt"], &record).is_empty());
    // The format really is asserted: a wrong value is rejected.
    record["created_at"] = serde_json::json!("2000-02-30T00:00:00Z");
    assert!(!errors(&validators["jail-receipt"], &record).is_empty());
}

// ---------------------------------------------------------------------------
// The §13.2 phase tuples
// ---------------------------------------------------------------------------

fn base_record(containment: Containment, os: Os) -> AttemptRecord {
    let created = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    AttemptRecord {
        attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
        revision: 1,
        platform: PlatformRecord {
            os,
            arch: "aarch64".to_owned(),
            kernel: "fixture-kernel".to_owned(),
        },
        jail: JailRecord {
            component: "ouro-jail".to_owned(),
            version: "0.0.0-test".to_owned(),
            backend: None,
            backend_version: None,
        },
        policy: PolicyRecord {
            name: "tool".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
            observe: ObserveMode::On,
            evidence: EvidenceMode::Strict,
            requirements: vec!["tree_termination".to_owned()],
            grants: Vec::new(),
        },
        containment,
        exec_observed: false,
        argv_digest: Some(format!("sha256:{}", "b".repeat(64))),
        applied: Applied {
            filesystem: None,
            network: AppliedNetwork {
                mode: match containment {
                    Containment::None => "host".to_owned(),
                    Containment::Pending => "pending".to_owned(),
                    Containment::Enforced => "none".to_owned(),
                },
                mechanism: None,
                allowed_hosts: Vec::new(),
            },
            syscalls: None,
            limits: Vec::new(),
            environment_names: Vec::new(),
            removed_environment_names: Vec::new(),
        },
        observer: CoverageSummary::unobserved().to_observer_record(),
        coverage: CoverageSummary::unobserved().to_coverage(),
        process: None,
        lifetime: Lifetime::pending(),
        outcome: Outcome::pending(),
        state_cleanup: StateCleanup::NotNeeded,
        cleanup_error: None,
        created_at: created,
        updated_at: created,
        errors: Vec::new(),
        credentials: Vec::new(),
    }
}

fn fixture_process() -> ProcessRecord {
    let mut value = serde_json::Map::new();
    value.insert("boot_id".to_owned(), serde_json::json!("fixture-boot"));
    value.insert("start_time_ticks".to_owned(), serde_json::json!("123456"));
    ProcessRecord {
        pid: 1234,
        identity: ProcessIdentity {
            kind: "linux_boot_start".to_owned(),
            value,
        },
    }
}

fn contained_application() -> Applied {
    Applied {
        filesystem: Some(AppliedFilesystem {
            mechanism: "fixture-mounts".to_owned(),
            protected_coverage: "existing_and_root".to_owned(),
            mounts: vec![AppliedMount {
                path: NativeString::Text("/work".to_owned()),
                mode: "rw".to_owned(),
            }],
        }),
        network: AppliedNetwork {
            mode: "none".to_owned(),
            mechanism: Some("fixture-network-namespace".to_owned()),
            allowed_hosts: Vec::new(),
        },
        syscalls: Some(AppliedSyscalls {
            mechanism: "fixture-seccomp".to_owned(),
            digest: format!("sha256:{}", "c".repeat(64)),
        }),
        limits: vec![AppliedLimit {
            key: "wall".to_owned(),
            requested: "30m".to_owned(),
            required: true,
            applied: true,
            mechanism: Some("monotonic-deadline".to_owned()),
            scope: Some("tree".to_owned()),
            hit: Some(false),
        }],
        environment_names: vec!["PATH".to_owned()],
        removed_environment_names: Vec::new(),
    }
}

fn assert_valid(receipt: &Receipt, validators: &BTreeMap<String, Validator>, label: &str) {
    let value = serde_json::to_value(receipt).expect("a receipt serializes");
    let failures = errors(&validators["jail-receipt"], &value);
    assert!(failures.is_empty(), "{label}: {failures:?}");
}

#[test]
fn tuple_refusal_before_boundary_creation() {
    let validators = validators();
    // Contained profile: pending / pending.
    let mut record = base_record(Containment::Pending, Os::Macos);
    let error = JailError::new(
        ErrorCode::UnsupportedPlatform,
        ErrorStage::Probing,
        Remediation::Unsupported,
        "execution is not implemented for this platform".to_owned(),
    );
    record.outcome = Outcome::refused(&error);
    record.errors.push(error.to_object());
    let receipt = record.receipt(Phase::Refused);
    assert_eq!(receipt.containment, Containment::Pending);
    assert_eq!(receipt.child_protection, ChildProtection::Pending);
    assert!(!receipt.exec_observed);
    assert_eq!(receipt.lifetime.boundary, "pending");
    assert_eq!(receipt.lifetime.verification_scope, None);
    assert_eq!(receipt.lifetime.tree_empty, None);
    assert_eq!(receipt.lifetime.verified_at, None);
    assert_eq!(receipt.outcome.kind, OutcomeKind::Refused);
    assert_valid(&receipt, &validators, "refused contained");

    // `none`: none / unprotected, even for a refusal (I08).
    let mut record = base_record(Containment::None, Os::Macos);
    record.outcome = Outcome::refused(&error);
    record.errors.push(error.to_object());
    let receipt = record.receipt(Phase::Refused);
    assert_eq!(receipt.containment, Containment::None);
    assert_eq!(receipt.child_protection, ChildProtection::Unprotected);
    assert_eq!(receipt.applied.network.mode, "host");
    assert_valid(&receipt, &validators, "refused none");
}

#[test]
fn tuple_contained_preparation_complete() {
    let validators = validators();
    let mut record = base_record(Containment::Enforced, Os::Linux);
    record.applied = contained_application();
    record.process = Some(fixture_process());
    record.lifetime = Lifetime {
        boundary: "pid_namespace".to_owned(),
        native: Some(NativeLifetime {
            os: Os::Linux,
            details: serde_json::Map::new(),
        }),
        tree_empty: None,
        verified_at: None,
        verification_scope: Some("attempt_tree".to_owned()),
        integrity: "verified".to_owned(),
    };
    let receipt = record.receipt(Phase::Prepared);
    assert_eq!(receipt.child_protection, ChildProtection::Enforced);
    assert!(
        !receipt.exec_observed,
        "prepared never means the target ran"
    );
    assert_eq!(
        receipt.lifetime.verification_scope.as_deref(),
        Some("attempt_tree")
    );
    assert_eq!(receipt.lifetime.tree_empty, None);
    assert_valid(&receipt, &validators, "prepared contained");
}

#[test]
fn tuple_none_preparation_complete_is_still_unprotected() {
    let validators = validators();
    let mut record = base_record(Containment::None, Os::Linux);
    record.process = Some(fixture_process());
    record.applied.limits = vec![AppliedLimit {
        key: "wall".to_owned(),
        requested: "2h".to_owned(),
        required: true,
        applied: true,
        mechanism: Some("boottime-deadline".to_owned()),
        scope: Some("tree".to_owned()),
        hit: Some(false),
    }];
    record.lifetime = Lifetime {
        boundary: "supervisor_cgroup".to_owned(),
        native: Some(NativeLifetime {
            os: Os::Linux,
            details: serde_json::Map::new(),
        }),
        tree_empty: None,
        verified_at: None,
        verification_scope: Some("registered_boundary".to_owned()),
        integrity: "verified".to_owned(),
    };
    let receipt = record.receipt(Phase::Prepared);
    assert_eq!(receipt.containment, Containment::None);
    assert_eq!(
        receipt.child_protection,
        ChildProtection::Unprotected,
        "I08: `none` is never upgraded"
    );
    assert_valid(&receipt, &validators, "prepared none");
}

#[test]
fn tuple_verified_settlement() {
    let validators = validators();
    let mut record = base_record(Containment::Enforced, Os::Linux);
    record.applied = contained_application();
    record.process = Some(fixture_process());
    record.exec_observed = true;
    record.outcome = Outcome {
        kind: OutcomeKind::Exited,
        code: Some(0),
        signal: None,
        cause: None,
        error: None,
    };
    record.lifetime = Lifetime {
        boundary: "pid_namespace".to_owned(),
        native: Some(NativeLifetime {
            os: Os::Linux,
            details: serde_json::Map::new(),
        }),
        tree_empty: Some(true),
        verified_at: Some(rfc3339_utc(SystemTime::UNIX_EPOCH)),
        verification_scope: Some("attempt_tree".to_owned()),
        integrity: "verified".to_owned(),
    };
    let receipt = record.receipt(Phase::Settled);
    assert!(receipt.exec_observed);
    assert_eq!(receipt.lifetime.tree_empty, Some(true));
    assert_valid(&receipt, &validators, "settled");

    // Settlement without tree proof is rejected by the contract, so the tuple
    // above is not merely a shape this code happens to emit.
    let mut without_proof = serde_json::to_value(&receipt).expect("serializes");
    without_proof["lifetime"]["tree_empty"] = serde_json::Value::Null;
    without_proof["lifetime"]["verified_at"] = serde_json::Value::Null;
    assert!(!errors(&validators["jail-receipt"], &without_proof).is_empty());
}

#[test]
fn a_receipt_always_announces_the_schema_identifier() {
    let record = base_record(Containment::Pending, Os::Macos);
    for phase in [
        Phase::Prepared,
        Phase::Enforced,
        Phase::Settled,
        Phase::Refused,
    ] {
        assert_eq!(record.receipt(phase).schema, SCHEMA_RECEIPT);
    }
}

// ---------------------------------------------------------------------------
// J4-R, R01 hardening
// ---------------------------------------------------------------------------

/// The semantic port is not vacuous: each rule rejects a receipt the schema
/// accepts, exactly as `validate_contract.py`'s `semantic_receipt` would.
#[test]
fn r01_the_semantic_checks_reject_what_the_schema_accepts() {
    let validators = validators();
    let base = read_json(&specs_dir().join("examples/receipt-agent-proxy-only.json"));
    let native = read_json(&specs_dir().join("examples/receipt-native-path.json"));
    let tool = read_json(&specs_dir().join("examples/receipt-tool.json"));
    common::semantic_receipt(&base).expect("the base is semantically valid");
    type Mutation = fn(&mut serde_json::Value);
    let cases: [(&str, &serde_json::Value, Mutation); 6] = [
        ("duplicate credential id", &base, |record| {
            let first = record["credentials"][0].clone();
            record["credentials"][1]["id"] = first["id"].clone();
        }),
        ("duplicate limit key", &base, |record| {
            record["applied"]["limits"][1]["key"] = "wall".into();
        }),
        (
            "coverage from a source the observer calls unsupported",
            &tool,
            |record| {
                record["observer"]["sources"]["wrapper"] = "unsupported".into();
            },
        ),
        ("byte form of valid UTF-8", &native, |record| {
            record["policy"]["grants"][0]["value"]["data"] = "L3dvcms=".into();
        }),
        ("noncanonical base64", &native, |record| {
            record["policy"]["grants"][0]["value"]["data"] = "L3dvcmsv/x==".into();
        }),
        ("a NUL in a native string", &native, |record| {
            record["policy"]["grants"][0]["value"]["data"] = "L3dvcgD/".into();
        }),
    ];
    for (label, base, mutate) in cases {
        let mut record = (*base).clone();
        mutate(&mut record);
        let failures = errors(&validators["jail-receipt"], &record);
        assert!(
            failures.is_empty(),
            "{label}: the schema must accept it for this to test the semantic rule: {failures:?}"
        );
        assert!(
            common::semantic_receipt(&record).is_err(),
            "{label}: the semantic checks must reject it"
        );
    }
}

/// §13.2 row 4: "Refusal after setup or proved exec error | refused | actual
/// application state | false | actual boundary / actual scope | true /
/// timestamp only after teardown verification; otherwise null / null".
#[test]
fn tuple_refusal_after_setup_or_proved_exec_error() {
    let validators = validators();
    let error = JailError::new(
        ErrorCode::ExecFailed,
        ErrorStage::Released,
        Remediation::Configuration,
        "the target exec failed with ENOENT".to_owned(),
    );
    let setup = |teardown_verified: bool, exec_error: bool| {
        let mut record = base_record(Containment::Enforced, Os::Linux);
        record.applied = contained_application();
        record.process = Some(fixture_process());
        record.lifetime = Lifetime {
            boundary: "pid_namespace".to_owned(),
            native: Some(NativeLifetime {
                os: Os::Linux,
                details: serde_json::Map::new(),
            }),
            tree_empty: teardown_verified.then_some(true),
            verified_at: teardown_verified.then(|| rfc3339_utc(SystemTime::UNIX_EPOCH)),
            verification_scope: Some("attempt_tree".to_owned()),
            integrity: "verified".to_owned(),
        };
        record.outcome = if exec_error {
            Outcome {
                error: Some(error.to_object()),
                ..Outcome::exec_error("ENOENT")
            }
        } else {
            Outcome::refused(&error)
        };
        record.errors.push(error.to_object());
        record
    };
    for (teardown_verified, exec_error) in
        [(true, true), (false, true), (true, false), (false, false)]
    {
        let label = format!("teardown verified {teardown_verified}, exec error {exec_error}");
        let receipt = setup(teardown_verified, exec_error).receipt(Phase::Refused);
        assert_eq!(receipt.phase, Phase::Refused, "{label}");
        assert_eq!(receipt.containment, Containment::Enforced, "{label}");
        assert_eq!(
            receipt.child_protection,
            ChildProtection::Enforced,
            "{label}"
        );
        assert!(!receipt.exec_observed, "{label}");
        assert_eq!(receipt.lifetime.boundary, "pid_namespace", "{label}");
        assert_eq!(
            receipt.lifetime.verification_scope.as_deref(),
            Some("attempt_tree"),
            "{label}"
        );
        assert_eq!(
            receipt.lifetime.tree_empty,
            teardown_verified.then_some(true),
            "{label}"
        );
        assert_eq!(
            receipt.lifetime.verified_at.is_some(),
            teardown_verified,
            "{label}"
        );
        assert_eq!(
            receipt.outcome.kind,
            if exec_error {
                OutcomeKind::ExecError
            } else {
                OutcomeKind::Refused
            },
            "{label}"
        );
        assert_valid(&receipt, &validators, &label);
        let value = serde_json::to_value(&receipt).expect("serializes");
        common::semantic_receipt(&value).expect("semantically valid");

        // The row's negative space: a verified tree without its time, and a
        // refusal that claims the target ran, are both rejected.
        if teardown_verified {
            let mut untimed = value.clone();
            untimed["lifetime"]["verified_at"] = serde_json::Value::Null;
            assert!(
                !errors(&validators["jail-receipt"], &untimed).is_empty(),
                "{label}: tree_empty true needs its verification time"
            );
        }
        let mut ran = value.clone();
        ran["exec_observed"] = true.into();
        assert!(
            !errors(&validators["jail-receipt"], &ran).is_empty(),
            "{label}: a refusal never observed the target's exec"
        );
    }
}
