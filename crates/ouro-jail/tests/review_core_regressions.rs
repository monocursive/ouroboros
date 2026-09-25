//! Adversarial regressions for the J1 portable core.
//!
//! Adopted from the review's `review_core_regressions.rs`. Every test states
//! the clause it is about, and each one failed against commit 8058039e.
//!
//! Two are adapted, with the reason on each: the review's cgroup test asserts
//! the opposite of decision A3, and the review's NUL test assumes a native
//! string containing NUL can be serialized at all, which this fix wave stops
//! at the writer rather than at the reader.

use std::path::PathBuf;

use ouro_jail::network::NetworkMode;
use ouro_jail::policy::{Layer, LayerOrigin, PolicyDelta, ProfileName, ResolveInputs, ScratchRoot};
use ouro_jail::profiles;
use ouro_jail::records::{NativeString, Os};

mod common;

fn inputs(workspace: &str, layers: Vec<Layer>) -> ResolveInputs {
    ResolveInputs {
        platform: Os::Linux,
        base_profile: ProfileName::Tool,
        policy_name: "tool".to_owned(),
        baseline: profiles::baseline(ProfileName::Tool, Os::Linux, &|_| None),
        workspace: workspace.as_bytes().to_vec(),
        scratch: ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers,
    }
}

fn project(delta: PolicyDelta, workspace: &str) -> Layer {
    Layer {
        origin: LayerOrigin::ProjectConfig("ouro.toml".to_owned()),
        base_dir: Some(workspace.as_bytes().to_vec()),
        key_prefix: "jail.".to_owned(),
        narrowing: true,
        delta,
    }
}

/// §6.3: "Equivalent semantic inputs have the same digest despite different
/// provenance." The workspace and scratch roots never passed through
/// normalization, so the same directory spelled four ways yielded four
/// digests, and a managed owner comparing `policy_digest` saw four plans.
#[test]
fn the_policy_digest_is_stable_across_equivalent_workspace_spellings() {
    let digest = |spelling: &str| {
        ouro_jail::policy::resolve(&inputs(spelling, Vec::new()))
            .expect("resolves")
            .digest
    };
    let canonical = digest("/srv/work");
    for spelling in [
        "/srv/work/",
        "/srv/work/.",
        "/srv//work",
        "/srv/other/../work",
    ] {
        assert_eq!(
            digest(spelling),
            canonical,
            "`{spelling}` names the same directory as /srv/work"
        );
    }
}

/// §6.3: "Compare authority after expansion and path resolution". The resolver
/// was purely lexical, so a workspace symlink pointing at a denied subtree was
/// accepted as an ordinary read-only narrowing.
///
/// Adapted only by building the symlink on disk: the review's version used a
/// path that does not exist, which now refuses for the weaker reason that the
/// object is unknown. This one proves the symlink rule itself.
#[test]
fn a_workspace_symlink_cannot_re_grant_a_denied_subtree() {
    let temp = common::private_tempdir();
    let root = std::fs::canonicalize(temp.path()).expect("canonical");
    std::fs::create_dir(root.join("secrets")).expect("secrets");
    std::os::unix::fs::symlink("secrets", root.join("alias")).expect("alias");
    let workspace = root.to_str().expect("a UTF-8 temporary path");

    let mut base = profiles::baseline(ProfileName::Tool, Os::Linux, &|_| None);
    base.read_only = Vec::new();
    base.deny_read.push(ouro_jail::policy::PathRef {
        root: ouro_jail::policy::RootToken::Workspace,
        path: NativeString::Text("secrets".to_owned()),
    });
    let mut resolve_inputs = inputs(
        workspace,
        vec![project(
            PolicyDelta {
                read_only: vec![b"alias".to_vec()],
                ..PolicyDelta::default()
            },
            workspace,
        )],
    );
    resolve_inputs.baseline = base;
    let error = ouro_jail::policy::resolve(&resolve_inputs)
        .expect_err("an unresolvable subset relationship must refuse, not widen");
    assert_eq!(error.code, ouro_jail::records::ErrorCode::PolicyWidening);
    assert!(error.message.contains("symlink"), "{}", error.message);
}

/// canonicalization.md: "Reject ... byte objects whose decoded bytes are valid
/// UTF-8 (they must use the string form)." The deserializer enforced that; the
/// serializer did not, so `NativeString::Bytes` of UTF-8 bytes emitted a form
/// the codec's own reader refuses, and the same path got two digests.
#[test]
fn the_native_string_codec_is_symmetric() {
    let text = NativeString::Text("abc".to_owned());
    let bytes = NativeString::Bytes(b"abc".to_vec());
    let encoded_text = serde_json::to_string(&text).expect("serializes");
    let encoded_bytes = serde_json::to_string(&bytes).expect("serializes");
    assert_eq!(
        encoded_text, encoded_bytes,
        "the same bytes must have exactly one canonical encoding"
    );
    serde_json::from_str::<NativeString>(&encoded_bytes)
        .expect("what the serializer writes, the deserializer must read");

    // And the digest that follows from it is one digest, not two.
    let digest = |value: &NativeString| {
        let json = serde_json::to_value(value).expect("serializes");
        ouro_jail::canonical::policy_digest(&json).expect("canonicalizes")
    };
    assert_eq!(digest(&text), digest(&bytes));
}

/// canonicalization.md: "Native values cannot contain NUL."
///
/// Adapted: the review asserted that a NUL must not survive a round trip,
/// which the reader already refused. The writer refuses too now, so a NUL can
/// never reach a receipt file in the first place. This asserts the stronger
/// property and would fail against a writer that emitted it.
#[test]
fn a_native_string_never_carries_a_nul() {
    let sneaky = NativeString::Text("a\u{0}b".to_owned());
    assert!(
        serde_json::to_string(&sneaky).is_err(),
        "a NUL is refused by the writer, not discovered by a later reader"
    );
    assert!(serde_json::to_string(&NativeString::Bytes(b"a\0b".to_vec())).is_err());
    // The reader still refuses one that reaches it from elsewhere.
    serde_json::from_str::<NativeString>("\"a\\u0000b\"")
        .expect_err("a NUL must not survive a round trip");
}

/// §6.4 and decision A3: the execution cgroup is required by a
/// cgroup-filtering observer or an explicit tree limit, not by observation as
/// such. The ptrace observer this milestone selected filters by tracee, not by
/// cgroup, so an observed `tool` with no explicit tree ceiling derives no
/// cgroup requirement.
///
/// Adapted: the review asserted the opposite. A3 decided it the other way, so
/// this states the decided rule and its boundary, and would fail if the
/// derivation started demanding a cgroup for every observed run.
#[test]
fn an_execution_cgroup_is_required_by_a_tree_limit_not_by_observation() {
    let observed = ouro_jail::policy::resolve(&inputs("/srv/work", Vec::new())).expect("resolves");
    assert_eq!(
        observed.snapshot.observation.mode,
        ouro_jail::records::ObserveMode::On,
        "observation is on by default"
    );
    assert!(
        !observed
            .requirements
            .iter()
            .any(|name| name == "execution_boundary"),
        "ptrace observation alone requires no cgroup: {:?}",
        observed.requirements
    );

    // An explicit tree ceiling does require one.
    let mut limited = inputs("/srv/work", Vec::new());
    limited.baseline.limits.pids = Some(ouro_jail::policy::Ceiling {
        value: 64,
        requested: "64".to_owned(),
        required: true,
    });
    let limited = ouro_jail::policy::resolve(&limited).expect("resolves");
    assert!(
        limited
            .requirements
            .iter()
            .any(|name| name == "execution_boundary"),
        "an explicit pids ceiling needs a cgroup: {:?}",
        limited.requirements
    );

    // And so does `none`, whose only lifetime boundary is that cgroup.
    let mut uncontained = inputs("/srv/work", Vec::new());
    uncontained.base_profile = ProfileName::None;
    uncontained.baseline = profiles::baseline(ProfileName::None, Os::Linux, &|_| None);
    let uncontained = ouro_jail::policy::resolve(&uncontained).expect("resolves");
    assert!(
        uncontained
            .requirements
            .iter()
            .any(|name| name == "execution_boundary")
    );
}

/// §6.3 narrowing: a project file may lower a ceiling, never raise one. The
/// unit game `30m` vs `1800s` vs `1800000ms` must compare equal, and §6.4's
/// grammar is `<digits><unit>` with nothing around it.
#[test]
fn equivalent_wall_spellings_compare_equal() {
    for spelling in ["30m", "1800s", "1800000ms"] {
        let ceilings =
            ouro_jail::config::ceilings_from_cli(&[format!("wall={spelling}")]).expect("parses");
        assert_eq!(ceilings.wall.expect("wall").value, 1_800_000, "{spelling}");
    }
    assert!(
        ouro_jail::config::ceilings_from_cli(&["wall= 30m ".to_owned()]).is_err(),
        "the limit grammar is `<digits><unit>`, with no surrounding whitespace"
    );
    assert!(
        ouro_jail::config::ceilings_from_cli(&["wall=\t30m".to_owned()]).is_err(),
        "nor a leading tab"
    );
}

/// §6.3: a non-proxy policy carries no allow rules, and `tool` rejects proxy
/// grants outright.
#[test]
fn a_tool_policy_rejects_a_host_grant() {
    let temp = common::private_tempdir();
    let root: PathBuf = std::fs::canonicalize(temp.path()).expect("canonical");
    let workspace = root.to_str().expect("a UTF-8 temporary path");
    let layer = project(
        PolicyDelta {
            network_allow: vec!["example.com:443".to_owned()],
            ..PolicyDelta::default()
        },
        workspace,
    );
    let error = ouro_jail::policy::resolve(&inputs(workspace, vec![layer])).expect_err("refuses");
    assert_eq!(error.key_path.as_deref(), Some("jail.network.allow"));
    assert_eq!(NetworkMode::None.authority_rank(), 0);
}
