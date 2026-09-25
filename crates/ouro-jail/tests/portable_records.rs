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
    AttemptRecord, ChildProtection, Containment, ControlMessage, ErrorCode, ErrorStage, Event,
    EvidenceMode, GateExpectation, GateFrame, JailError, JailRecord, Lifetime, NativeLifetime,
    NativeString, ObserveMode, Os, Outcome, OutcomeKind, Phase, PlatformRecord, PolicyRecord,
    ProcessIdentity, ProcessRecord, Receipt, Remediation, SCHEMA_RECEIPT, StateCleanup,
    parse_release, rfc3339_utc, rfc3339_utc_from_unix, semantic,
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

/// Builds one validator per checked-in schema, every one registered by `$id`
/// so that `jail-event.schema.json` can `$ref` the shared envelope and
/// `jail-control.schema.json` the receipt's outcome and error.
fn validators() -> BTreeMap<String, Validator> {
    let schemas = common::load_schemas(&specs_dir()).unwrap_or_else(|error| panic!("{error}"));
    // J5-C: the six wire schemas of §13 and §8.2 (J5-D adds the doctor's).
    for stem in [
        "event",
        "jail-event",
        "jail-receipt",
        "policy-snapshot",
        "jail-gate",
        "jail-control",
    ] {
        assert!(
            schemas.contains_key(stem),
            "{stem}.schema.json accompanies the specification"
        );
    }

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

/// J5-C: the schema an example file is an instance of, by its name's prefix,
/// exactly as `validate_contract.py` dispatches it. `doctor-*` examples are
/// J5-D's and carry their own schema; they are not wire records here.
fn schema_of(name: &str) -> Option<&'static str> {
    [
        ("event-", "jail-event"),
        ("receipt-", "jail-receipt"),
        ("gate-", "jail-gate"),
        ("control-", "jail-control"),
    ]
    .into_iter()
    .find_map(|(prefix, schema)| name.starts_with(prefix).then_some(schema))
}

fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .expect("a file name")
}

#[test]
fn r01_every_example_round_trips_through_the_rust_types() {
    let files = record_files();
    assert!(files.len() >= 12, "the corpus is present: {files:?}");
    let mut typed = 0usize;
    for path in files {
        let original = read_json(&path);
        let name = file_name(&path);
        let produced = match schema_of(name) {
            Some("jail-event") => {
                let event: Event = serde_json::from_value(original.clone())
                    .unwrap_or_else(|error| panic!("{name} does not fit `Event`: {error}"));
                serde_json::to_value(&event).expect("an event serializes")
            }
            Some("jail-receipt") => {
                let receipt: Receipt = serde_json::from_value(original.clone())
                    .unwrap_or_else(|error| panic!("{name} does not fit `Receipt`: {error}"));
                serde_json::to_value(&receipt).expect("a receipt serializes")
            }
            Some("jail-gate") => {
                let frame: GateFrame = serde_json::from_value(original.clone())
                    .unwrap_or_else(|error| panic!("{name} does not fit `GateFrame`: {error}"));
                serde_json::to_value(&frame).expect("a gate frame serializes")
            }
            Some("jail-control") => {
                let message: ControlMessage = serde_json::from_value(original.clone())
                    .unwrap_or_else(|error| {
                        panic!("{name} does not fit `ControlMessage`: {error}")
                    });
                serde_json::to_value(&message).expect("a control message serializes")
            }
            _ => continue,
        };
        typed += 1;
        assert_eq!(produced, original, "{name} did not round-trip unchanged");
    }
    assert!(typed >= 12, "every wire example has a Rust type");
}

#[test]
fn r01_every_example_validates_against_its_schema() {
    let validators = validators();
    for path in record_files() {
        let record = read_json(&path);
        let name = file_name(&path);
        let Some(key) = schema_of(name) else {
            continue;
        };
        let failures = errors(&validators[key], &record);
        assert!(failures.is_empty(), "{name}: {failures:?}");
        // J4-R, R01: the rules the schema cannot state, as validate_contract.py
        // checks them. J5-C: events too (their native byte strings).
        let semantic = match key {
            "jail-receipt" => semantic::receipt(&record),
            "jail-event" => semantic::event(&record),
            _ => Vec::new(),
        };
        assert!(
            semantic.is_empty(),
            "{name} fails the semantic checks: {semantic:?}"
        );
    }
}

/// J5-C, R01 and §17 "Before J5": one example per kind of event the jail
/// writes, so every source-specific rule is exercised on a positive instance.
/// A kind is (source, operation, completion) for a result, plus the decision
/// for a proxy result and `fields.kind` for a wrapper note. The note kinds are
/// the ones the product writes: `lifecycle` (`supervisor.rs`), `limit`
/// (`platform/linux/audit.rs`), `lifetime` (`platform/linux/uncontained.rs`),
/// `helper` (`platform/linux/agent.rs`) and `coverage_gap`
/// (`platform/linux/audit.rs`, `trace.rs`).
#[test]
fn r01_every_event_kind_has_an_example() {
    let mut kinds = std::collections::BTreeSet::new();
    for path in record_files() {
        if schema_of(file_name(&path)) != Some("jail-event") {
            continue;
        }
        let event = read_json(&path);
        let text = |value: &serde_json::Value| value.as_str().unwrap_or("-").to_owned();
        let detail = match event["source"].as_str() {
            Some("proxy") => text(&event["decision"]),
            Some("wrapper") if event["operation"] == "note" => text(&event["fields"]["kind"]),
            Some("audit") if event["operation"] == "fs.deny" => {
                text(&event["fields"]["attempted_operation"])
            }
            _ => "-".to_owned(),
        };
        kinds.insert(format!(
            "{} {} {} {}",
            text(&event["source"]),
            text(&event["operation"]),
            text(&event["outcome"]["completion"]),
            detail
        ));
    }
    for expected in [
        "audit proc.exec exec_transition -",
        "audit proc.exec syscall_return -",
        "audit proc.exit process_exit -",
        "audit fs.create syscall_return -",
        "audit fs.write syscall_return -",
        "audit fs.rename syscall_return -",
        "audit fs.unlink syscall_return -",
        "audit fs.deny syscall_return fs.write",
        "audit fs.deny syscall_return net.connect",
        "audit net.connect syscall_return -",
        "proxy net.connect proxy_close allow",
        "proxy net.connect proxy_close deny",
        "wrapper jail.receipt wrapper -",
        "wrapper note wrapper lifecycle",
        "wrapper note wrapper limit",
        "wrapper note wrapper lifetime",
        "wrapper note wrapper helper",
        "wrapper note wrapper coverage_gap",
    ] {
        assert!(
            kinds.contains(expected),
            "no example of `{expected}`; the examples cover {kinds:#?}"
        );
    }
}

// ---------------------------------------------------------------------------
// J5-C: the semantic corpus, shared with validate_contract.py
// ---------------------------------------------------------------------------

/// Applies one corpus change: `{"path": [...], "value": v}` sets (creating a
/// missing final key), `{"path": [...], "delete": true}` removes a key or an
/// array element. The same operations as `validate_contract.py`'s `apply`.
fn apply(record: &mut serde_json::Value, change: &serde_json::Value) {
    let path = change["path"].as_array().expect("a path");
    // An empty path replaces the whole instance (the pair cases).
    let Some((last, parents)) = path.split_last() else {
        *record = change["value"].clone();
        return;
    };
    let mut cursor = record;
    for segment in parents {
        cursor = step(cursor, segment);
    }
    let delete = change["delete"].as_bool().unwrap_or(false);
    match cursor {
        serde_json::Value::Array(items) => {
            let position = index_of(last);
            if delete {
                items.remove(position);
            } else {
                items[position] = change["value"].clone();
            }
        }
        serde_json::Value::Object(map) => {
            let key = last.as_str().expect("an object key");
            if delete {
                map.remove(key).expect("the deleted key exists");
            } else {
                map.insert(key.to_owned(), change["value"].clone());
            }
        }
        other => panic!("cannot change inside {other}"),
    }
}

fn corpus_instance(case: &serde_json::Value, key: &str) -> serde_json::Value {
    let mut record = read_json(&specs_dir().join(case[key].as_str().expect("a base path")));
    for change in case["changes"].as_array().expect("changes") {
        apply(&mut record, change);
    }
    record
}

fn rules_of(violations: &[semantic::Violation]) -> std::collections::BTreeSet<String> {
    violations.iter().map(|v| v.rule.to_owned()).collect()
}

/// Every case in `fixtures/semantic-cases.json` gets exactly the rule set the
/// corpus names (empty for a positive case), from the library checker that
/// every live test uses. `validate_contract.py` runs the same corpus through
/// its own port, so the two cannot drift apart. A negative case must be one
/// the schemas accept, or it would test the schema rather than the rule; and
/// every rule the library knows has a negative case and a citation.
#[test]
fn r01_the_semantic_corpus_gets_the_verdicts_it_expects() {
    let validators = validators();
    let corpus = read_json(&specs_dir().join("fixtures/semantic-cases.json"));
    let cited: std::collections::BTreeSet<String> = corpus["rules"]
        .as_object()
        .expect("the rule citations")
        .keys()
        .cloned()
        .collect();
    let known: std::collections::BTreeSet<String> = semantic::RULES
        .iter()
        .map(|(rule, _)| (*rule).to_owned())
        .collect();
    assert_eq!(
        cited, known,
        "the corpus cites exactly the rules the library checks"
    );
    let mut negative: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut positive = 0usize;
    for case in corpus["cases"].as_array().expect("the cases") {
        let name = case["name"].as_str().expect("a case name");
        let expected: std::collections::BTreeSet<String> = case["violations"]
            .as_array()
            .expect("the expected violations")
            .iter()
            .map(|rule| rule.as_str().expect("a rule id").to_owned())
            .collect();
        let record = corpus_instance(case, "base");
        let (schema, instances): (&str, Vec<&serde_json::Value>) =
            match case["check"].as_str().expect("a check") {
                "receipt" => ("jail-receipt", vec![&record]),
                "trace" => (
                    "jail-event",
                    record.as_array().expect("a trace").iter().collect(),
                ),
                "control" => (
                    "jail-control",
                    record.as_array().expect("a transcript").iter().collect(),
                ),
                other => panic!("case `{name}`: unknown check {other}"),
            };
        for instance in &instances {
            let failures = errors(&validators[schema], instance);
            assert!(
                failures.is_empty(),
                "case `{name}`: the schema must accept it for this to test a semantic rule: {failures:?}"
            );
        }
        let found = match case["check"].as_str() {
            Some("receipt") => semantic::receipt(&record),
            Some("trace") => {
                let events = record.as_array().expect("a trace");
                let mut found = semantic::trace(events);
                // A trace case may name the attempt's final receipt: then the
                // trace must end on that receipt's note (§13.3).
                if let Some(receipt) = case.get("receipt").and_then(serde_json::Value::as_str) {
                    let receipt = read_json(&specs_dir().join(receipt));
                    found.extend(semantic::trace_ends_with(events, &receipt));
                }
                found
            }
            _ => semantic::control(record.as_array().expect("a transcript")),
        };
        assert_eq!(rules_of(&found), expected, "case `{name}`: {found:#?}");
        if expected.is_empty() {
            positive += 1;
        }
        negative.extend(expected);
    }
    assert!(positive > 0, "the corpus has positive cases");
    assert_eq!(
        negative, known,
        "every rule has at least one negative case, and no case names an unknown rule"
    );
}

/// J5-C review item 1: a second schema file declaring an `$id` another file
/// already declares would silently replace it in the registry (a frozen
/// schema shadowed by an unfrozen one, with no frozen sha256 changing). Both
/// loaders refuse it; this is the Rust loader's negative case, and the spec
/// directory itself is loaded through the same function.
#[test]
fn r01_the_schema_loader_refuses_two_files_with_one_id() {
    let dir = common::private_tempdir();
    for name in ["a.schema.json", "b.schema.json"] {
        std::fs::write(
            dir.path().join(name),
            br#"{"$id": "urn:ouro:schema:event:1", "title": "shadow"}"#,
        )
        .unwrap();
    }
    let refused = common::load_schemas(dir.path()).expect_err("a duplicate $id refuses");
    assert!(
        refused.contains("urn:ouro:schema:event:1"),
        "the refusal names the identifier: {refused}"
    );
    assert!(common::load_schemas(&specs_dir()).is_ok());
}

// ---------------------------------------------------------------------------
// J5-C, X02: the gate frame corpus, shared with validate_contract.py
// ---------------------------------------------------------------------------

/// Every frame in `fixtures/gate-frames.json` gets the verdict the corpus
/// expects from the supervisor's own parser (§8.2); `validate_contract.py`
/// holds its port to the same corpus and checks the parsed object against
/// `jail-gate.schema.json`.
#[test]
fn x02_the_gate_frame_corpus_gets_the_verdicts_it_expects() {
    use base64::Engine as _;
    let corpus = read_json(&specs_dir().join("fixtures/gate-frames.json"));
    let expected = GateExpectation {
        attempt_id: corpus["expect"]["attempt_id"]
            .as_str()
            .expect("an attempt")
            .to_owned(),
        policy_digest: corpus["expect"]["policy_digest"]
            .as_str()
            .expect("a digest")
            .to_owned(),
    };
    let validators = validators();
    let cases = corpus["cases"].as_array().expect("the cases");
    assert!(cases.len() >= 15, "the corpus is present");
    for case in cases {
        let name = case["name"].as_str().expect("a case name");
        let bytes = match (case.get("frame"), case.get("frame_base64")) {
            (Some(frame), None) => frame.as_str().expect("a frame").as_bytes().to_vec(),
            (None, Some(data)) => base64::engine::general_purpose::STANDARD
                .decode(data.as_str().expect("base64"))
                .expect("valid base64"),
            _ => panic!("case `{name}` has one frame"),
        };
        let verdict = match parse_release(&bytes, &expected) {
            Ok(frame) => {
                let value = serde_json::to_value(&frame).expect("serializes");
                let failures = errors(&validators["jail-gate"], &value);
                assert!(
                    failures.is_empty(),
                    "case `{name}`: an accepted frame is a schema-valid release: {failures:?}"
                );
                "release".to_owned()
            }
            Err(error) => error.code.as_str().to_owned(),
        };
        assert_eq!(
            verdict,
            case["result"].as_str().expect("a result"),
            "case `{name}`"
        );
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
        // A path segment is an object key or an array index; a change sets
        // (creating a missing final key) or deletes, exactly as
        // `validate_contract.py`'s `apply` does.
        for change in case["changes"].as_array().expect("changes") {
            apply(&mut record, change);
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
            // Nonzero trailing bits: the schema's pattern accepts it; Python's
            // lenient decoder needs the re-encoding comparison to reject it,
            // the strict Rust decoder already refuses it.
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
