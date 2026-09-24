//! J5-D: the milestone-1 freeze file holds (jail-v1 §16).
//!
//! §16: "Freeze the Rust toolchain, Cargo.lock, backend version/hashes,
//! filter digest, observer object/build provenance and tested host manifest
//! with the milestone report. Re-run relevant conformance when any of these
//! change. A dependency update must not silently broaden mounted files or
//! allow-hosts."
//!
//! `docs/specs/jail-v1/milestone-1-freeze.toml` is written by `cargo xtask
//! freeze` from files. Each test here recomputes one frozen value from the
//! tree, through the jail's own constants and digest functions where they
//! exist, and fails when it drifts: the change is then a decision (rerun
//! conformance, regenerate), never a silent one.

use std::path::{Path, PathBuf};

use sha2::Digest as _;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root exists")
}

fn freeze() -> toml::Value {
    let path = repo_root().join("docs/specs/jail-v1/milestone-1-freeze.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    toml::from_str(&text).expect("the freeze file is TOML")
}

fn read_toml(relative: &str) -> toml::Value {
    let text = std::fs::read_to_string(repo_root().join(relative))
        .unwrap_or_else(|error| panic!("{relative}: {error}"));
    toml::from_str(&text).unwrap_or_else(|error| panic!("{relative}: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn evidence(name: &str) -> String {
    std::fs::read_to_string(repo_root().join("docs/specs/jail-v1/evidence").join(name))
        .unwrap_or_else(|error| panic!("{name}: {error}"))
}

/// The digests an evidence table lists, in order.
fn table_digests(table: &str) -> Vec<String> {
    table
        .lines()
        .filter_map(|line| line.split_once("digest: ").map(|(_, value)| value.trim()))
        .filter(|value| value.starts_with("sha256:"))
        .map(str::to_owned)
        .collect()
}

fn frozen_str<'a>(value: &'a toml::Value, path: &[&str]) -> &'a str {
    let mut node = value;
    for key in path {
        node = node
            .get(key)
            .unwrap_or_else(|| panic!("the freeze has no `{}`", path.join(".")));
    }
    node.as_str()
        .unwrap_or_else(|| panic!("the freeze's `{}` is not a string", path.join(".")))
}

fn frozen_list(value: &toml::Value, path: &[&str]) -> Vec<String> {
    let mut node = value;
    for key in path {
        node = node
            .get(key)
            .unwrap_or_else(|| panic!("the freeze has no `{}`", path.join(".")));
    }
    node.as_array()
        .unwrap_or_else(|| panic!("the freeze's `{}` is not a list", path.join(".")))
        .iter()
        .map(|item| item.as_str().expect("a string").to_owned())
        .collect()
}

fn text(value: Option<&toml::Value>) -> Option<&str> {
    value.and_then(toml::Value::as_str)
}

const REGENERATE: &str = "a frozen value changed: re-run the conformance suite (§16), then \
                          `cargo xtask freeze --doctor <that run's doctor.json>`";

#[test]
fn the_freeze_names_itself() {
    let freeze = freeze();
    assert_eq!(
        frozen_str(&freeze, &["schema"]),
        "ouro.jail.milestone-freeze/1"
    );
    assert_eq!(freeze["milestone"].as_integer(), Some(1));
}

#[test]
fn the_toolchain_is_the_frozen_one() {
    let freeze = freeze();
    let toolchain = read_toml("rust-toolchain.toml");
    let workspace = read_toml("Cargo.toml");
    assert_eq!(
        toolchain["toolchain"]["channel"].as_str(),
        Some(frozen_str(&freeze, &["toolchain", "channel"])),
        "rust-toolchain.toml: {REGENERATE}"
    );
    assert_eq!(
        workspace["workspace"]["package"]["rust-version"].as_str(),
        Some(frozen_str(&freeze, &["toolchain", "rust_version"])),
        "Cargo.toml rust-version: {REGENERATE}"
    );
}

#[test]
fn the_lock_file_is_the_frozen_one() {
    let freeze = freeze();
    let lock = std::fs::read(repo_root().join("Cargo.lock")).expect("Cargo.lock");
    assert_eq!(
        sha256_hex(&lock),
        frozen_str(&freeze, &["cargo_lock", "sha256"]),
        "Cargo.lock: {REGENERATE}"
    );
    let parsed: toml::Value = toml::from_str(&String::from_utf8_lossy(&lock)).expect("TOML");
    assert_eq!(
        parsed["package"].as_array().map(Vec::len),
        freeze["cargo_lock"]["packages"]
            .as_integer()
            .and_then(|count| usize::try_from(count).ok()),
        "Cargo.lock package count"
    );
}

/// The filters: the frozen digest is the evidence table's and the one this
/// build computes, and the tables are the frozen bytes.
#[test]
fn the_filter_digests_are_the_frozen_ones() {
    use ouro_jail::platform::linux::seccomp::{self, AgentVariant};
    let freeze = freeze();
    assert_eq!(
        frozen_str(&freeze, &["filters", "arch"]),
        seccomp::TABLE_ARCH
    );
    let tool = evidence("seccomp-table-tool-x86_64.txt");
    let agent = evidence("seccomp-table-agent-x86_64.txt");
    let namespace = evidence("seccomp-table-agent-namespace-x86_64.txt");
    for (key, table, index, built) in [
        (
            "tool",
            &tool,
            0,
            seccomp::tool_baseline().expect("builds").digest(),
        ),
        (
            "agent",
            &agent,
            0,
            seccomp::agent_baseline(AgentVariant::UnprivilegedInner)
                .expect("builds")
                .digest(),
        ),
        (
            "agent_namespace",
            &namespace,
            0,
            seccomp::agent_baseline(AgentVariant::NamespaceInner)
                .expect("builds")
                .digest(),
        ),
    ] {
        let frozen = frozen_str(&freeze, &["filters", key]);
        assert_eq!(
            table_digests(table).get(index).map(String::as_str),
            Some(frozen),
            "{key}'s evidence table: {REGENERATE}"
        );
        assert_eq!(built, frozen, "{key} as this build makes it: {REGENERATE}");
    }
    // The mediation filter both agent tables list after the baseline.
    let mediation = frozen_str(&freeze, &["filters", "agent_mediation"]);
    for table in [&agent, &namespace] {
        assert_eq!(
            table_digests(table).get(1).map(String::as_str),
            Some(mediation),
            "{REGENERATE}"
        );
    }
    assert_eq!(
        seccomp::mediation_filter().expect("builds").digest(),
        mediation,
        "the mediation filter as this build makes it: {REGENERATE}"
    );
    // The launcher installs it through unixpeer, which exists on Linux.
    #[cfg(target_os = "linux")]
    assert_eq!(
        ouro_jail::platform::linux::unixpeer::filter_digest(),
        mediation,
        "the mediation filter the launcher installs: {REGENERATE}"
    );
    for (name, text) in [
        ("seccomp-table-tool-x86_64.txt", &tool),
        ("seccomp-table-agent-x86_64.txt", &agent),
        ("seccomp-table-agent-namespace-x86_64.txt", &namespace),
    ] {
        assert_eq!(
            sha256_hex(text.as_bytes()),
            frozen_str(&freeze, &["filters", "table_sha256", name]),
            "{name}: {REGENERATE}"
        );
    }
}

#[test]
fn the_closed_set_is_the_frozen_one() {
    let freeze = freeze();
    let table = evidence("closed-set-x86_64.txt");
    assert_eq!(
        frozen_str(&freeze, &["closed_set", "name"]),
        ouro_jail::observer::CoverageSummary::linux_closed_set()
    );
    assert_eq!(
        table_digests(&table).first().map(String::as_str),
        Some(frozen_str(&freeze, &["closed_set", "narrowing_filter"])),
        "the closed-set table's narrowing filter: {REGENERATE}"
    );
    assert_eq!(
        sha256_hex(table.as_bytes()),
        frozen_str(&freeze, &["closed_set", "table_sha256"]),
        "closed-set-x86_64.txt: {REGENERATE}"
    );
    // The table this build traces with, where the tracer exists.
    #[cfg(target_os = "linux")]
    assert_eq!(
        sha256_hex(ouro_jail::platform::linux::tracer::closed_set_table().as_bytes()),
        frozen_str(&freeze, &["closed_set", "table_sha256"]),
        "the closed set this build traces: {REGENERATE}"
    );
}

/// §16: "must not silently broaden mounted files". The contained profiles'
/// runtime roots and protected segments are the jail's own constants.
#[test]
fn the_contained_mount_baselines_are_the_frozen_ones() {
    let freeze = freeze();
    assert_eq!(
        frozen_list(&freeze, &["mounts", "linux_runtime_roots"]),
        ouro_jail::profiles::LINUX_RUNTIME_ROOTS,
        "profiles.rs LINUX_RUNTIME_ROOTS: {REGENERATE}"
    );
    assert_eq!(
        frozen_list(&freeze, &["mounts", "protected_segments"]),
        ouro_jail::profiles::PROTECTED_SEGMENTS,
        "profiles.rs PROTECTED_SEGMENTS: {REGENERATE}"
    );
    // The backend's own grants exist only in the Linux build.
    #[cfg(target_os = "linux")]
    {
        use ouro_jail::platform::linux::bwrap;
        assert_eq!(
            frozen_list(&freeze, &["mounts", "backend_runtime_roots"]),
            bwrap::RUNTIME_ROOTS,
            "bwrap.rs RUNTIME_ROOTS: {REGENERATE}"
        );
        assert_eq!(
            frozen_list(&freeze, &["mounts", "backend_etc_paths"]),
            bwrap::ETC_PATHS,
            "bwrap.rs ETC_PATHS: {REGENERATE}"
        );
    }
}

/// §16: "must not silently broaden mounted files or allow-hosts". What each
/// bundled launch profile copies or binds into the sandbox, and the hosts
/// it allows, are the frozen ones; a new or removed profile is a change too.
#[test]
fn the_bundled_launch_profiles_are_the_frozen_ones() {
    let freeze = freeze();
    let frozen = freeze["launch_profile"]
        .as_array()
        .expect("[[launch_profile]] entries");
    let directory = repo_root().join("crates/ouro-jail/profiles/launch");
    let mut files: Vec<String> = std::fs::read_dir(&directory)
        .expect("the bundled profiles")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(".toml"))
        .map(|name| format!("crates/ouro-jail/profiles/launch/{name}"))
        .collect();
    files.sort();
    let frozen_files: Vec<&str> = frozen
        .iter()
        .map(|entry| entry["file"].as_str().expect("a file"))
        .collect();
    assert_eq!(frozen_files, files, "the bundled profiles: {REGENERATE}");

    for entry in frozen {
        let file = entry["file"].as_str().expect("a file");
        let profile = read_toml(file);
        let list = |value: Option<&toml::Value>| -> Vec<String> {
            value
                .and_then(toml::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().expect("a string").to_owned())
                        .collect()
                })
                .unwrap_or_default()
        };
        assert_eq!(text(profile.get("name")), text(entry.get("name")), "{file}");
        assert_eq!(text(profile.get("jail")), text(entry.get("jail")), "{file}");
        assert_eq!(
            text(profile.get("state_var")),
            text(entry.get("state_var")),
            "{file} state_var: {REGENERATE}"
        );
        assert_eq!(
            profile
                .get("home_is_state")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false),
            entry["home_is_state"].as_bool().expect("a bool"),
            "{file} home_is_state: {REGENERATE}"
        );
        assert_eq!(
            list(profile.get("state_subdirs")),
            list(entry.get("state_subdirs")),
            "{file} state_subdirs: {REGENERATE}"
        );
        assert_eq!(
            list(
                profile
                    .get("network")
                    .and_then(|network| network.get("allow"))
            ),
            list(entry.get("network_allow")),
            "{file} network.allow: {REGENERATE}"
        );
        // Review F3: the environment it sets in the sandbox.
        let environment = profile
            .get("environment")
            .map_or_else(|| serde_json::json!({}), json);
        let recorded: serde_json::Value =
            serde_json::from_str(text(entry.get("environment")).expect("an environment"))
                .expect("the frozen environment is JSON");
        assert_eq!(environment, recorded, "{file} environment: {REGENERATE}");
        let credentials: Vec<(String, String, String, String)> = profile
            .get("credentials")
            .and_then(toml::Value::as_table)
            .map(|table| {
                table
                    .iter()
                    .map(|(id, credential)| {
                        let field =
                            |key: &str| credential[key].as_str().expect("a string").to_owned();
                        (id.clone(), field("source"), field("dest"), field("mode"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let frozen_credentials: Vec<(String, String, String, String)> = entry
            .get("credential")
            .and_then(toml::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|credential| {
                        let field =
                            |key: &str| credential[key].as_str().expect("a string").to_owned();
                        (field("id"), field("source"), field("dest"), field("mode"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            credentials, frozen_credentials,
            "{file} credentials: {REGENERATE}"
        );
    }
}

/// The frozen wire schemas: J5-C's `frozen-schemas.toml` entries, copied,
/// and each file still the frozen bytes. Until that file exists the section
/// is empty; it may not claim a freeze that has not happened.
#[test]
fn the_frozen_schemas_are_the_frozen_ones() {
    let freeze = freeze();
    let section = freeze["frozen_schemas"]
        .as_table()
        .expect("a [frozen_schemas] section");
    let source = repo_root().join("docs/specs/jail-v1/frozen-schemas.toml");
    if !source.exists() {
        assert!(
            section.is_empty(),
            "no frozen-schemas.toml exists, so the freeze records no frozen schema"
        );
        return;
    }
    let manifest = read_toml("docs/specs/jail-v1/frozen-schemas.toml");
    let expected = manifest
        .get("frozen")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let recorded = section
        .get("entry")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(recorded, expected, "frozen-schemas.toml: {REGENERATE}");
    for entry in &recorded {
        let (Some(file), Some(sha256)) = (
            entry.get("file").and_then(toml::Value::as_str),
            entry.get("sha256").and_then(toml::Value::as_str),
        ) else {
            continue;
        };
        let bytes = std::fs::read(repo_root().join("docs/specs/jail-v1").join(file))
            .unwrap_or_else(|error| panic!("{file}: {error}"));
        assert_eq!(sha256_hex(&bytes), sha256, "{file}: {REGENERATE}");
    }
}

/// Review F4: a recorded tested run is the milestone run, validated
/// strictly: ready, Linux x86_64, an optimised build without debug
/// assertions, a clean named revision, the backend it used, and an explicit
/// list of the facts that were unknown (never a stand-in value). Whether it
/// tested exactly this tree is `cargo xtask freeze --check`'s question (the
/// milestone gate), so ordinary development after the milestone is not
/// failed by this test.
#[test]
fn a_recorded_tested_run_is_the_milestone_run() {
    let freeze = freeze();
    let Some(tested) = freeze.get("tested") else {
        // Its absence is stated in the file, never silent.
        let text =
            std::fs::read_to_string(repo_root().join("docs/specs/jail-v1/milestone-1-freeze.toml"))
                .expect("the freeze file");
        assert!(text.contains("No tested run is recorded"), "{text}");
        return;
    };
    assert_eq!(tested["ready"].as_bool(), Some(true));
    assert_eq!(frozen_str(tested, &["platform_os"]), "linux");
    assert_eq!(frozen_str(tested, &["platform_arch"]), "x86_64");
    assert_eq!(frozen_str(tested, &["target"]), "x86_64-unknown-linux-gnu");
    assert_eq!(frozen_str(tested, &["opt_level"]), "3");
    assert_eq!(tested["debug_assertions"].as_bool(), Some(false));
    assert_eq!(tested["dirty"].as_bool(), Some(false));
    let revision = frozen_str(tested, &["revision"]);
    assert!(
        revision.len() == 40
            && revision.bytes().all(|b| b.is_ascii_hexdigit())
            && revision.bytes().any(|b| b != b'0'),
        "{revision}"
    );
    let inputs = frozen_str(tested, &["inputs"]);
    assert!(
        inputs.starts_with("sha256:") && inputs.len() == 71,
        "{inputs}"
    );
    for key in ["path", "version", "sha256"] {
        assert!(!frozen_str(tested, &["backend", key]).is_empty(), "{key}");
    }
    assert!(
        tested["host"].is_table(),
        "the whole host object is recorded"
    );
    let unknown = frozen_list(tested, &["unknown"]);
    for path in &unknown {
        // A fact listed as unknown is absent from the record.
        let mut node = Some(tested);
        for part in path.split('.') {
            node = node.and_then(|value| value.get(part));
        }
        assert!(node.is_none(), "{path} is both unknown and recorded");
    }
    assert!(!frozen_list(tested, &["verification"]).is_empty());
}

/// Review F3: what every contained profile passes from the operator's
/// environment, and the PATH it gives the child.
#[test]
fn the_contained_environment_is_the_frozen_one() {
    let freeze = freeze();
    assert_eq!(
        frozen_list(&freeze, &["contained", "environment_names"]),
        ouro_jail::profiles::CONTAINED_ENVIRONMENT_NAMES,
        "profiles.rs CONTAINED_ENVIRONMENT_NAMES: {REGENERATE}"
    );
    assert_eq!(
        frozen_str(&freeze, &["contained", "path"]),
        ouro_jail::profiles::CONTAINED_PATH,
        "profiles.rs CONTAINED_PATH: {REGENERATE}"
    );
}

/// Review F3: each built-in profile's resolved baseline, all four.
#[test]
fn the_built_in_baselines_are_the_frozen_ones() {
    let freeze = freeze();
    let frozen = freeze["baseline"].as_array().expect("[[baseline]] entries");
    let baselines = ouro_jail::platform::linux::freeze::baselines().expect("they resolve");
    assert_eq!(
        frozen
            .iter()
            .map(|entry| entry["profile"].as_str().expect("a profile"))
            .collect::<Vec<_>>(),
        ["agent", "tool", "build", "none"]
    );
    for (entry, baseline) in frozen.iter().zip(&baselines) {
        let profile = baseline.profile.as_str();
        assert_eq!(entry["profile"].as_str(), Some(profile));
        let snapshot: serde_json::Value =
            serde_json::from_str(entry["snapshot"].as_str().expect("a snapshot"))
                .expect("the frozen snapshot is JSON");
        assert_eq!(
            baseline.snapshot, snapshot,
            "{profile}'s baseline: {REGENERATE}"
        );
        assert_eq!(
            entry["digest"].as_str(),
            Some(baseline.digest.as_str()),
            "{profile}'s baseline digest: {REGENERATE}"
        );
    }
}

/// Review F3: the backend plan each contained profile renders (Linux, where
/// the backend exists; the macOS legs check the rest).
#[cfg(target_os = "linux")]
#[test]
fn the_backend_plans_are_the_frozen_ones() {
    let freeze = freeze();
    let frozen = freeze["backend_plan"].as_array().expect("[[backend_plan]]");
    let plans = ouro_jail::platform::linux::freeze::backend_plans().expect("they render");
    assert_eq!(frozen.len(), plans.len(), "{REGENERATE}");
    for (entry, (profile, argv)) in frozen.iter().zip(&plans) {
        assert_eq!(entry["profile"].as_str(), Some(*profile));
        let recorded: Vec<String> = entry["argv"]
            .as_array()
            .expect("argv")
            .iter()
            .map(|arg| arg.as_str().expect("a string").to_owned())
            .collect();
        assert_eq!(&recorded, argv, "{profile}'s backend plan: {REGENERATE}");
    }
}

/// A TOML value as JSON, written here independently of the generator.
fn json(value: &toml::Value) -> serde_json::Value {
    match value {
        toml::Value::String(text) => serde_json::json!(text),
        toml::Value::Integer(number) => serde_json::json!(number),
        toml::Value::Float(number) => serde_json::json!(number),
        toml::Value::Boolean(flag) => serde_json::json!(flag),
        toml::Value::Datetime(time) => serde_json::json!(time.to_string()),
        toml::Value::Array(items) => serde_json::Value::Array(items.iter().map(json).collect()),
        toml::Value::Table(table) => serde_json::Value::Object(
            table
                .iter()
                .map(|(key, value)| (key.clone(), json(value)))
                .collect(),
        ),
    }
}

/// Review F14: every manifest's profiles, dependency selections (versions,
/// features, default-features) and feature definitions.
#[test]
fn the_manifests_are_the_frozen_ones() {
    let freeze = freeze();
    let frozen = freeze["manifest"].as_array().expect("[[manifest]] entries");
    let mut files = vec!["Cargo.toml".to_owned()];
    let mut crates: Vec<String> = std::fs::read_dir(repo_root().join("crates"))
        .expect("crates")
        .map(|entry| entry.expect("an entry").path().join("Cargo.toml"))
        .filter(|path| path.is_file())
        .map(|path| {
            path.strip_prefix(repo_root())
                .expect("inside")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    crates.sort();
    files.extend(crates);
    assert_eq!(
        frozen
            .iter()
            .map(|entry| entry["file"].as_str().expect("a file").to_owned())
            .collect::<Vec<_>>(),
        files,
        "the manifests: {REGENERATE}"
    );
    for entry in frozen {
        let file = entry["file"].as_str().expect("a file");
        let manifest = read_toml(file);
        let mut expected = serde_json::Map::new();
        for key in [
            "profile",
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
            "target",
            "features",
            "patch",
            "replace",
        ] {
            if let Some(value) = manifest.get(key) {
                expected.insert(key.to_owned(), json(value));
            }
        }
        if let Some(value) = manifest
            .get("workspace")
            .and_then(|workspace| workspace.get("dependencies"))
        {
            expected.insert("workspace.dependencies".to_owned(), json(value));
        }
        let recorded: serde_json::Value =
            serde_json::from_str(entry["sections"].as_str().expect("sections"))
                .expect("the frozen sections are JSON");
        assert_eq!(
            serde_json::Value::Object(expected),
            recorded,
            "{file}: {REGENERATE}"
        );
    }
}
