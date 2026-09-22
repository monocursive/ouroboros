//! P01: canonical bytes, digests and the golden fixture corpus.
//!
//! Compares the resolver's output with `docs/specs/jail-v1/fixtures/*`: both
//! canonical TOML inputs must resolve to the golden snapshot, the RFC 8785
//! bytes must equal `policy.jcs` byte for byte, and both digests must equal the
//! checked-in values. Reordering sets or keys and changing provenance must
//! preserve the hash; changing a limit, a grant, an environment value or the
//! argv order must change the right digest.

use std::path::{Path, PathBuf};

use ouro_jail::canonical;
use ouro_jail::config;
use ouro_jail::policy::{
    EnvBinding, EnvironmentSnapshot, Layer, LayerOrigin, PathRef, PolicyDelta, ProfileBaseline,
    ProfileName, ResolveInputs, Resolved, ScratchRoot,
};
use ouro_jail::profiles;
use ouro_jail::records::{NativeString, Os};

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs/jail-v1")
        .canonicalize()
        .expect("the checked-in specification directory exists")
}

fn read_json(relative: &str) -> serde_json::Value {
    let path = specs_dir().join(relative);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()))
}

fn read_text(relative: &str) -> String {
    let path = specs_dir().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

fn read_bytes(relative: &str) -> Vec<u8> {
    let path = specs_dir().join(relative);
    std::fs::read(&path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

/// Decodes the fixtures' native-string codec: a JSON string or the base64
/// object. This mirrors `native_bytes` in `validate_contract.py`.
fn native_bytes(value: &serde_json::Value) -> Vec<u8> {
    let parsed: NativeString =
        serde_json::from_value(value.clone()).expect("the fixture uses the native-string codec");
    parsed.as_bytes().to_vec()
}

/// The synthetic baseline of `fixtures/canonical-context.json`, with the
/// built-in `tool` defaults for the keys the context does not fix.
fn fixture_baseline(context: &serde_json::Value) -> ProfileBaseline {
    let mut baseline = profiles::baseline(ProfileName::Tool, Os::Linux, &|_| None);
    let declared = &context["baseline"];
    let refs = |key: &str| -> Vec<PathRef> {
        declared[key]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|item| serde_json::from_value(item.clone()).expect("a path reference"))
            .collect()
    };
    baseline.read_write = refs("read_write");
    baseline.read_only = refs("read_only");
    baseline.deny_read = refs("deny_read");
    baseline.protected_segments = declared["protected_segments"]
        .as_array()
        .expect("protected segments")
        .iter()
        .map(|item| item.as_str().expect("a segment name").to_owned())
        .collect();
    let bindings: Vec<EnvBinding> = declared["environment"]["bindings"]
        .as_array()
        .expect("bindings")
        .iter()
        .map(|item| serde_json::from_value(item.clone()).expect("a binding"))
        .collect();
    baseline.environment = EnvironmentSnapshot {
        inherit_host: declared["environment"]["inherit_host"]
            .as_bool()
            .expect("inherit_host"),
        bindings,
    };
    baseline
}

struct FixtureOptions {
    profile_file: &'static str,
    provenance_variant: usize,
    reorder_profile_sets: bool,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        FixtureOptions {
            profile_file: "canonical-input.toml",
            provenance_variant: 0,
            reorder_profile_sets: false,
        }
    }
}

/// Resolves the fixture context exactly as canonicalization.md describes it:
/// the built-in `tool` baseline, then the operator profile file, then the
/// command line's byte-valued `--deny-read`.
fn resolve_fixture(options: &FixtureOptions) -> Resolved {
    let context = read_json("fixtures/canonical-context.json");
    let profile_directory = context["profile_directory"]
        .as_str()
        .expect("profile_directory")
        .as_bytes()
        .to_vec();
    let workspace = context["workspace"]
        .as_str()
        .expect("workspace")
        .as_bytes()
        .to_vec();

    let file = config::parse_policy_file(&read_text(&format!("fixtures/{}", options.profile_file)))
        .expect("the canonical fixture is a valid policy file");
    assert_eq!(file.extends, "tool", "the fixture extends the tool profile");
    let mut delta = config::delta_from_sections(
        "",
        &file.filesystem,
        &file.network,
        &file.limits,
        &file.observation,
    )
    .expect("the fixture's sections parse");
    if options.reorder_profile_sets {
        delta.read_only.reverse();
        delta.deny_read.reverse();
    }

    let provenance = context["provenance_variants"][options.provenance_variant]
        .as_str()
        .expect("a provenance variant")
        .to_owned();

    let cli_deny: Vec<Vec<u8>> = context["cli_deny_read"]
        .as_array()
        .expect("cli_deny_read")
        .iter()
        .map(native_bytes)
        .collect();

    let inputs = ResolveInputs {
        platform: Os::Linux,
        base_profile: ProfileName::Tool,
        policy_name: "tool".to_owned(),
        baseline: fixture_baseline(&context),
        workspace,
        scratch: ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers: vec![
            Layer {
                origin: LayerOrigin::OperatorProfileFile(provenance),
                base_dir: Some(profile_directory),
                key_prefix: String::new(),
                narrowing: true,
                delta,
            },
            Layer {
                origin: LayerOrigin::CommandLine,
                base_dir: None,
                key_prefix: String::new(),
                narrowing: false,
                delta: PolicyDelta {
                    deny_read: cli_deny,
                    ..PolicyDelta::default()
                },
            },
        ],
    };
    ouro_jail::policy::resolve(&inputs).expect("the fixture policy resolves")
}

#[test]
fn p01_both_canonical_inputs_resolve_to_the_golden_snapshot() {
    let expected = read_json("fixtures/policy-snapshot.json");
    for profile_file in ["canonical-input.toml", "canonical-equivalent.toml"] {
        let resolved = resolve_fixture(&FixtureOptions {
            profile_file,
            ..FixtureOptions::default()
        });
        let produced = resolved
            .snapshot
            .to_canonical_value()
            .expect("the snapshot canonicalizes");
        assert_eq!(
            produced, expected,
            "{profile_file} did not resolve to fixtures/policy-snapshot.json"
        );
    }
}

#[test]
fn p01_canonical_bytes_equal_the_golden_jcs_file() {
    let expected = read_bytes("fixtures/policy.jcs");
    assert!(
        !expected.ends_with(b"\n"),
        "the golden file has no trailing newline"
    );
    let produced = resolve_fixture(&FixtureOptions::default())
        .snapshot
        .canonical_bytes()
        .expect("the snapshot canonicalizes");
    assert_eq!(
        produced,
        expected,
        "canonical bytes differ:\n produced {}\n expected {}",
        String::from_utf8_lossy(&produced),
        String::from_utf8_lossy(&expected)
    );
}

#[test]
fn p01_both_digests_equal_the_checked_in_values() {
    let digests = read_json("fixtures/digests.json");
    let resolved = resolve_fixture(&FixtureOptions::default());
    assert_eq!(
        resolved.digest,
        digests["policy_digest"].as_str().expect("policy_digest")
    );

    let argv: Vec<Vec<u8>> = digests["argv"]
        .as_array()
        .expect("argv")
        .iter()
        .map(native_bytes)
        .collect();
    let preimage = canonical::argv_preimage(&argv);
    let hex: String = preimage.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        digests["argv_preimage_hex"]
            .as_str()
            .expect("argv_preimage_hex")
    );
    assert_eq!(
        canonical::argv_digest(&argv),
        digests["argv_digest"].as_str().expect("argv_digest")
    );
}

#[test]
fn p01_reordering_sets_and_changing_provenance_preserve_the_hash() {
    let base = resolve_fixture(&FixtureOptions::default());

    let equivalent_file = resolve_fixture(&FixtureOptions {
        profile_file: "canonical-equivalent.toml",
        ..FixtureOptions::default()
    });
    assert_eq!(
        base.digest, equivalent_file.digest,
        "a reordered, equivalently spelled file has the same digest"
    );

    let reordered = resolve_fixture(&FixtureOptions {
        reorder_profile_sets: true,
        ..FixtureOptions::default()
    });
    assert_eq!(
        base.digest, reordered.digest,
        "set order is not part of the digest"
    );

    let other_provenance = resolve_fixture(&FixtureOptions {
        provenance_variant: 1,
        ..FixtureOptions::default()
    });
    assert_ne!(
        base.provenance, other_provenance.provenance,
        "the two variants really do differ in provenance"
    );
    assert_eq!(
        base.digest, other_provenance.digest,
        "provenance is never hash input"
    );
}

#[test]
fn p01_semantic_changes_change_the_right_digest() {
    let base = resolve_fixture(&FixtureOptions::default());
    let snapshot = base
        .snapshot
        .to_canonical_value()
        .expect("the snapshot canonicalizes");

    // Walks object keys and array indices alike so a binding can be mutated.
    let mutate = |path: &[&str], value: serde_json::Value| {
        let mut changed = snapshot.clone();
        let mut cursor = &mut changed;
        for key in path {
            cursor = match cursor {
                serde_json::Value::Array(items) => {
                    let index: usize = key.parse().expect("an array index");
                    items.get_mut(index).expect("the index exists")
                }
                other => other.get_mut(key).expect("the key exists"),
            };
        }
        *cursor = value;
        canonical::policy_digest(&changed).expect("canonicalizes")
    };

    assert_ne!(
        mutate(&["limits", "wall", "value"], serde_json::json!("300001")),
        base.digest,
        "a changed limit changes the policy digest"
    );
    assert_ne!(
        mutate(
            &["environment", "bindings", "0", "value"],
            serde_json::json!("changed")
        ),
        base.digest,
        "a changed environment value changes the policy digest"
    );

    let mut with_grant = snapshot.clone();
    with_grant["filesystem"]["read_write"]
        .as_array_mut()
        .expect("read_write")
        .push(serde_json::json!({"root": "host", "path": "/srv/other"}));
    assert_ne!(
        canonical::policy_digest(&with_grant).expect("canonicalizes"),
        base.digest,
        "an added grant changes the policy digest"
    );

    let digests = read_json("fixtures/digests.json");
    let argv: Vec<Vec<u8>> = digests["argv"]
        .as_array()
        .expect("argv")
        .iter()
        .map(native_bytes)
        .collect();
    let mut reversed = argv.clone();
    reversed.reverse();
    assert_ne!(
        canonical::argv_digest(&reversed),
        canonical::argv_digest(&argv),
        "argv order is part of the argv digest"
    );
}

#[test]
fn p01_non_utf8_paths_and_argv_survive_as_the_base64_object() {
    let resolved = resolve_fixture(&FixtureOptions::default());
    let snapshot = resolved
        .snapshot
        .to_canonical_value()
        .expect("the snapshot canonicalizes");
    let deny = snapshot["filesystem"]["deny_read"]
        .as_array()
        .expect("deny_read");
    let byte_entry = deny
        .iter()
        .find(|entry| entry["path"].is_object())
        .expect("the byte-valued deny_read entry survives resolution");
    assert_eq!(byte_entry["root"], serde_json::json!("workspace"));
    assert_eq!(
        byte_entry["path"],
        serde_json::json!({"encoding": "base64", "data": "/w=="}),
        "a non-UTF-8 path encodes as the base64 object, not as lossy text"
    );

    let digests = read_json("fixtures/digests.json");
    let argv: Vec<Vec<u8>> = digests["argv"]
        .as_array()
        .expect("argv")
        .iter()
        .map(native_bytes)
        .collect();
    assert_eq!(argv[3], vec![0xffu8], "the byte argument survives decoding");
    assert_eq!(argv[2], Vec::<u8>::new(), "an empty argument is preserved");
}
