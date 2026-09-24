//! `version --json` announces the schema identifiers, and they are the ones the
//! checked-in schema files declare (jail-v1 §4: "the schema identifiers that
//! `ouro version --json` announces are constants tested against those files").
//!
//! Five schemas state their own identifier in `properties.schema.const`
//! (receipt, event, policy snapshot and, since J5, gate and control). The
//! remaining three have no schema file of their own, so they are pinned
//! against the artefacts that do carry them: the digest fixture's domain names,
//! the snapshot schema's `network.ruleset` enum and the specification text.
//!
//! J5-C, §13 and §17 "Before J5": the wire schemas are frozen. The frozen set,
//! with each file's `$id`, wire identifier and sha256, is
//! `docs/specs/jail-v1/frozen-schemas.toml`; a frozen file whose bytes change
//! fails here, and says whether it kept its identifier (a breaking change that
//! needs a new one, §13) or took a new one (which needs its own entry).

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root exists")
}

fn specs_dir() -> PathBuf {
    repo_root().join("docs/specs/jail-v1")
}

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    serde_json::from_str(&text).expect("valid JSON")
}

fn version_json() -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_ouro-jail"))
        .args(["version", "--json"])
        .output()
        .expect("the binary runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "version exits 0 on every platform: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("version --json prints JSON on stdout")
}

#[test]
fn the_announced_schema_identifiers_match_the_checked_in_schema_files() {
    let announced = version_json();
    let schemas = &announced["schemas"];

    for (key, file) in [
        ("receipt", "jail-receipt.schema.json"),
        ("event", "event.schema.json"),
        ("policy_snapshot", "policy-snapshot.schema.json"),
        // J5-C: the gate frame and the control message have schemas of their
        // own now (§8.2).
        ("gate", "jail-gate.schema.json"),
        ("control", "jail-control.schema.json"),
    ] {
        let schema = read_json(&specs_dir().join(file));
        let declared = schema["properties"]["schema"]["const"]
            .as_str()
            .unwrap_or_else(|| panic!("{file} declares its identifier"));
        assert_eq!(
            schemas[key].as_str(),
            Some(declared),
            "the announced `{key}` identifier must equal the one in {file}"
        );
    }

    // The jail producer restriction has no `schema` const of its own; it
    // restricts the shared envelope, whose identifier is announced as `event`.
    let jail_event = read_json(&specs_dir().join("jail-event.schema.json"));
    let shared_id = read_json(&specs_dir().join("event.schema.json"))["$id"]
        .as_str()
        .expect("the shared envelope has an $id")
        .to_owned();
    assert!(
        serde_json::to_string(&jail_event)
            .expect("serializes")
            .contains(&shared_id),
        "the producer restriction references the shared envelope it restricts"
    );

    // `ouro.jail.policy/1` is the digest domain pinned by the golden fixture.
    let digests = read_json(&specs_dir().join("fixtures/digests.json"));
    assert_eq!(
        schemas["policy"].as_str(),
        digests["policy_domain"].as_str(),
        "the policy identifier is the digest domain of the golden fixture"
    );

    // `ouro.jail.network/1` is the ruleset the snapshot schema admits.
    let snapshot_schema = read_json(&specs_dir().join("policy-snapshot.schema.json"));
    let ruleset = snapshot_schema["properties"]["network"]["properties"]["ruleset"]["enum"]
        .as_array()
        .expect("the ruleset enum");
    assert!(
        ruleset.contains(&serde_json::Value::String(
            schemas["network"].as_str().expect("a string").to_owned()
        )),
        "the announced network ruleset is one the snapshot schema admits"
    );

    // The remaining one is named only by the normative text.
    let spec = std::fs::read_to_string(repo_root().join("docs/specs/jail-v1.md"))
        .expect("the specification is checked in");
    let identifier = schemas["policy_file"].as_str().expect("a string");
    let named_in_spec = spec.contains(identifier);
    let named_in_canonicalization =
        std::fs::read_to_string(specs_dir().join("canonicalization.md"))
            .expect("the canonical byte rules are checked in")
            .contains(identifier);
    assert!(
        named_in_spec || named_in_canonicalization,
        "`{identifier}` must be named by the normative documents"
    );
}

#[test]
fn the_announced_closed_set_is_the_one_the_specification_names() {
    let announced = version_json();
    // J5-D: the running platform's closed set; macOS has none in this
    // milestone (§3.2), so it announces null rather than Linux's name.
    let expected = if cfg!(target_os = "linux") {
        serde_json::json!("linux-closed-v1")
    } else {
        serde_json::Value::Null
    };
    assert_eq!(announced["observation"]["closed_set"], expected);
    let spec = std::fs::read_to_string(repo_root().join("docs/specs/jail-v1.md"))
        .expect("the specification is checked in");
    assert!(spec.contains("linux-closed-v1"));
}

#[test]
fn version_text_mode_names_every_schema_too() {
    let output = Command::new(env!("CARGO_BIN_EXE_ouro-jail"))
        .arg("version")
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).expect("UTF-8");
    for identifier in [
        "ouro.jail.receipt/1",
        "ouro.event/1",
        "ouro.jail.policy/1",
        "ouro.jail.policy-snapshot/1",
        "ouro.jail.policy-file/1",
        "ouro.jail.gate/1",
        "ouro.jail.control/1",
        "ouro.jail.network/1",
    ] {
        assert!(text.contains(identifier), "text mode omits {identifier}");
    }
}

// ---------------------------------------------------------------------------
// J5-C: the schema freeze (§13: "After freeze, a breaking semantic change
// needs a new schema identifier"; §17: "Before J5: ... freeze the wire
// versions")
// ---------------------------------------------------------------------------

fn frozen_manifest() -> toml::Value {
    let text = std::fs::read_to_string(specs_dir().join("frozen-schemas.toml"))
        .expect("docs/specs/jail-v1/frozen-schemas.toml is checked in");
    toml::from_str(&text).expect("frozen-schemas.toml is TOML")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The frozen entries: `(file, $id, wire identifier, sha256)`.
fn frozen_entries() -> Vec<(String, String, String, String)> {
    let manifest = frozen_manifest();
    assert_eq!(
        manifest["schema"].as_str(),
        Some("ouro.jail.frozen-schemas/1"),
        "the freeze manifest names its own format"
    );
    manifest["frozen"]
        .as_array()
        .expect("[[frozen]] entries")
        .iter()
        .map(|entry| {
            let field = |key: &str| {
                entry[key]
                    .as_str()
                    .unwrap_or_else(|| panic!("a frozen entry lacks `{key}`: {entry}"))
                    .to_owned()
            };
            (
                field("file"),
                field("id"),
                field("identifier"),
                field("sha256"),
            )
        })
        .collect()
}

/// A frozen file's bytes are the bytes recorded at the freeze. When they are
/// not, the failure says which of the two legitimate paths applies: revert,
/// or (for a breaking change) a new `$id` and wire identifier with an entry of
/// their own. A change that keeps the frozen identifier is the one §13 forbids.
#[test]
fn a_frozen_schema_never_changes_under_its_frozen_identifier() {
    let entries = frozen_entries();
    assert!(!entries.is_empty(), "the freeze lists its schemas");
    for (file, id, _, sha256) in &entries {
        let path = specs_dir().join(file);
        let bytes =
            std::fs::read(&path).unwrap_or_else(|error| panic!("reading frozen {file}: {error}"));
        let actual = sha256_hex(&bytes);
        if actual == *sha256 {
            continue;
        }
        let schema: serde_json::Value = serde_json::from_slice(&bytes).expect("a JSON schema");
        if schema["$id"].as_str() == Some(id.as_str()) {
            panic!(
                "{file} changed (sha256 {actual}, frozen {sha256}) but still declares the frozen \
                 identifier {id}. A frozen schema never changes under its identifier (jail-v1 \
                 §13): revert the change, or give the schema a new $id and wire identifier and \
                 record the new file in frozen-schemas.toml."
            );
        }
        panic!(
            "{file} now declares {} instead of its frozen identifier {id}: record the new \
             identifier and its sha256 {actual} in frozen-schemas.toml",
            schema["$id"]
        );
    }
}

/// Every schema in the specification directory is either frozen or named as
/// not a milestone-1 wire record, so a new schema cannot slip in unfrozen;
/// each frozen entry's identifiers are the ones the file and the binary use.
#[test]
fn every_wire_schema_is_frozen_with_the_identifiers_the_binary_announces() {
    let manifest = frozen_manifest();
    let entries = frozen_entries();
    let unfrozen: Vec<String> = manifest
        .get("unfrozen")
        .and_then(toml::Value::as_array)
        .map(|list| {
            list.iter()
                .map(|entry| entry["file"].as_str().expect("an unfrozen file").to_owned())
                .collect()
        })
        .unwrap_or_default();
    let mut on_disk: Vec<String> = std::fs::read_dir(specs_dir())
        .expect("the specification directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(".schema.json"))
        .collect();
    on_disk.sort();
    for name in &on_disk {
        assert!(
            entries.iter().any(|(file, ..)| file == name) || unfrozen.contains(name),
            "{name} is neither frozen nor listed as unfrozen in frozen-schemas.toml"
        );
    }
    let announced = version_json();
    let announced: Vec<&str> = announced["schemas"]
        .as_object()
        .expect("the announced identifiers")
        .values()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let mut ids = std::collections::BTreeSet::new();
    for (file, id, identifier, _) in &entries {
        assert!(ids.insert(id.clone()), "{id} is frozen twice");
        let schema = read_json(&specs_dir().join(file));
        assert_eq!(schema["$id"].as_str(), Some(id.as_str()), "{file}'s $id");
        let title = schema["title"]
            .as_str()
            .expect("a frozen schema has a title");
        assert!(
            !title.to_lowercase().contains("draft"),
            "{file} is frozen and its title still says draft: {title}"
        );
        // The wire identifier: the file's own `schema` const, or for the
        // producer restriction, the envelope's it restricts.
        let declared = schema["properties"]["schema"]["const"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                let restricted = schema["allOf"][0]["$ref"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{file} declares no identifier"));
                entries
                    .iter()
                    .find(|(_, other, ..)| other == restricted)
                    .map(|(_, _, identifier, _)| identifier.clone())
                    .unwrap_or_else(|| panic!("{file} restricts {restricted}, which is not frozen"))
            });
        assert_eq!(&declared, identifier, "{file}'s wire identifier");
        assert!(
            announced.contains(&identifier.as_str()),
            "`version --json` announces {identifier}"
        );
    }
}
