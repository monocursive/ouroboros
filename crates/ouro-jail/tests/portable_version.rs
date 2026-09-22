//! `version --json` announces the schema identifiers, and they are the ones the
//! checked-in schema files declare (jail-v1 §4: "the schema identifiers that
//! `ouro version --json` announces are constants tested against those files").
//!
//! The four schemas state their own identifier in `properties.schema.const`.
//! The remaining four have no schema file of their own, so they are pinned
//! against the artefacts that do carry them: the digest fixture's domain names,
//! the snapshot schema's `network.ruleset` enum and the specification text.

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

    // The remaining two are named only by the specification text.
    let spec = std::fs::read_to_string(repo_root().join("docs/specs/jail-v1.md"))
        .expect("the specification is checked in");
    for key in ["gate", "control", "policy_file"] {
        let identifier = schemas[key].as_str().expect("a string");
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
}

#[test]
fn the_announced_closed_set_is_the_one_the_specification_names() {
    let announced = version_json();
    assert_eq!(
        announced["observation"]["closed_set"].as_str(),
        Some("linux-closed-v1")
    );
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
