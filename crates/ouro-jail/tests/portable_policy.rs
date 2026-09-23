//! P02: every widening category of the §6.3 table refuses with the exact key
//! path, and every narrowing category is allowed.
//!
//! The narrowing layer is a workspace-root `ouro.toml`, so the key paths carry
//! the `jail.` prefix a project file uses, and the layer is untrusted: §2 says
//! the workspace and its project configuration belong to the contained party.
//! That is why these tests use a real directory rather than a made-up path.
//! The interesting attacks are spellings, and a spelling only means something
//! against a filesystem: `alias -> secrets`, `SECRETS` on a case-folding
//! volume, and `escape -> /` are the three the resolver has to see through.

use std::path::{Path, PathBuf};

use ouro_jail::network::{HostRule, NetworkMode};
use ouro_jail::policy::{
    Ceiling, Ceilings, Layer, LayerOrigin, PathRef, PolicyDelta, ProfileBaseline, ProfileName,
    ProtectedCoverage, ResolveInputs, Resolved, RootToken, ScratchRoot,
};
use ouro_jail::profiles;
use ouro_jail::records::{ErrorCode, EvidenceMode, JailError, NativeString, ObserveMode, Os};

mod common;

/// A workspace with the shape the battery uses: a denied subtree, a read-only
/// one, a symlink to the denied subtree and a symlink out of the workspace.
struct Workspace {
    _temp: tempfile::TempDir,
    root: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let temp = common::private_tempdir();
        // Resolve now: on macOS the temporary directory is reached through
        // `/var`, a symlink to `/private/var`.
        let root = std::fs::canonicalize(temp.path()).expect("canonical");
        std::fs::create_dir(root.join("secrets")).expect("secrets");
        std::fs::create_dir(root.join("vendor")).expect("vendor");
        std::fs::create_dir(root.join("src")).expect("src");
        std::os::unix::fs::symlink("secrets", root.join("alias")).expect("alias");
        std::os::unix::fs::symlink("/", root.join("escape")).expect("escape");
        Workspace { _temp: temp, root }
    }

    fn bytes(&self) -> Vec<u8> {
        use std::os::unix::ffi::OsStrExt as _;
        self.root.as_os_str().as_bytes().to_vec()
    }

    fn reference(&self, path: &str) -> PathRef {
        PathRef {
            root: RootToken::Workspace,
            path: NativeString::Text(path.to_owned()),
        }
    }

    /// Resolves `tool` (or `agent`) with a project layer carrying `delta`.
    fn resolve_project(
        &self,
        profile: ProfileName,
        tweak: impl FnOnce(&mut ProfileBaseline),
        delta: PolicyDelta,
    ) -> Result<Resolved, JailError> {
        let mut baseline = profiles::baseline(profile, Os::Linux, &|_| None);
        // A deterministic baseline: no host runtime roots, one writable
        // workspace, and `secrets` denied the way the operator profile in the
        // battery denies it.
        baseline.read_only = Vec::new();
        baseline.read_write = vec![self.reference("")];
        baseline.deny_read = vec![self.reference("secrets")];
        tweak(&mut baseline);
        let inputs = ResolveInputs {
            platform: Os::Linux,
            base_profile: profile,
            policy_name: profile.as_str().to_owned(),
            baseline,
            workspace: self.bytes(),
            scratch: ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: vec![Layer {
                origin: LayerOrigin::ProjectConfig("ouro.toml".to_owned()),
                base_dir: Some(self.bytes()),
                key_prefix: "jail.".to_owned(),
                narrowing: true,
                delta,
            }],
        };
        ouro_jail::policy::resolve(&inputs)
    }
}

fn expect_widening(result: Result<Resolved, JailError>, key: &str) {
    match result {
        Ok(_) => panic!("expected a refusal naming `{key}`"),
        Err(error) => {
            assert_eq!(error.code, ErrorCode::PolicyWidening, "for key {key}");
            assert_eq!(
                error.key_path.as_deref(),
                Some(key),
                "the refusal must name the exact key path"
            );
            assert_eq!(error.exit_code(), 125, "a refusal before exec exits 125");
        }
    }
}

fn ceiling(value: u64, requested: &str) -> Option<Ceiling> {
    Some(Ceiling {
        value,
        requested: requested.to_owned(),
        required: true,
    })
}

#[test]
fn project_host_narrowing_replaces_the_base_set_including_empty() {
    let workspace = Workspace::new();
    for allow in [vec!["api.example.com:443".to_owned()], Vec::new()] {
        let resolved = workspace
            .resolve_project(
                ProfileName::Agent,
                |base| {
                    base.network_allow = HostRule::parse("*.example.com:443").unwrap();
                },
                PolicyDelta {
                    network_allow: allow.clone(),
                    network_allow_present: true,
                    ..PolicyDelta::default()
                },
            )
            .unwrap();
        assert_eq!(resolved.snapshot.network.allow, allow);
    }
    let resolved = workspace
        .resolve_project(
            ProfileName::Agent,
            |base| {
                base.network_allow = HostRule::parse("*.example.com:443").unwrap();
            },
            PolicyDelta::default(),
        )
        .unwrap();
    assert_eq!(resolved.snapshot.network.allow, vec!["*.example.com:443"]);
}

fn read_only(paths: &[&str]) -> PolicyDelta {
    PolicyDelta {
        read_only: paths.iter().map(|path| path.as_bytes().to_vec()).collect(),
        ..PolicyDelta::default()
    }
}

fn read_write(paths: &[&str]) -> PolicyDelta {
    PolicyDelta {
        read_write: paths.iter().map(|path| path.as_bytes().to_vec()).collect(),
        ..PolicyDelta::default()
    }
}

// ---------------------------------------------------------------------------
// H1 and A4: identity, not spelling
// ---------------------------------------------------------------------------

#[test]
fn p02_a_denied_subtree_cannot_be_re_granted_by_any_spelling() {
    let workspace = Workspace::new();
    for (label, spelling) in [
        ("the denied path itself", "./secrets"),
        ("a trailing slash", "./secrets/"),
        ("repeated slashes", "./secrets//"),
        ("dot components", "./vendor/../secrets"),
        ("an absolute spelling", "secrets"),
    ] {
        expect_widening(
            workspace.resolve_project(ProfileName::Tool, |_| {}, read_only(&[spelling])),
            "jail.filesystem.read_only",
        );
        let _ = label;
    }
}

#[test]
fn p02_a_symlink_component_refuses_because_its_target_is_the_childs_choice() {
    let workspace = Workspace::new();
    for spelling in ["./alias", "./escape", "./alias/deeper"] {
        let error = workspace
            .resolve_project(ProfileName::Tool, |_| {}, read_only(&[spelling]))
            .expect_err("a symlink cannot be compared by identity");
        assert_eq!(error.code, ErrorCode::PolicyWidening, "{spelling}");
        assert!(
            error.message.contains("symlink"),
            "`{spelling}` must say why: {}",
            error.message
        );
    }
}

#[test]
fn p02_a_case_variation_is_caught_by_identity_on_a_case_folding_volume() {
    let workspace = Workspace::new();
    let folds = std::fs::symlink_metadata(workspace.root.join("SECRETS")).is_ok();
    let result = workspace.resolve_project(ProfileName::Tool, |_| {}, read_only(&["./SECRETS"]));
    let error = result.expect_err("`SECRETS` must not become a grant");
    assert_eq!(error.code, ErrorCode::PolicyWidening);
    if folds {
        assert!(
            error.message.contains("whatever its spelling"),
            "on a case-folding volume the identity rule is what catches it: {}",
            error.message
        );
    } else {
        // On a case-sensitive volume the object simply does not exist, which
        // §6.3 also refuses: an unknown subset relationship never widens.
        assert!(
            error.message.contains("unknown subset"),
            "on a case-sensitive volume it is an unknown object: {}",
            error.message
        );
    }
}

#[test]
fn p02_a_grant_beneath_a_denied_subtree_refuses_at_any_depth() {
    let workspace = Workspace::new();
    std::fs::create_dir_all(workspace.root.join("secrets/a/b")).expect("a deep path");
    // The old rule made denial the most specific match, so naming a path one
    // component deeper than the denial re-granted it.
    for spelling in ["./secrets/a", "./secrets/a/b"] {
        expect_widening(
            workspace.resolve_project(ProfileName::Tool, |_| {}, read_write(&[spelling])),
            "jail.filesystem.read_write",
        );
    }
}

/// §6.3 and §9.1: an absent path is a refusal for a grant and a narrowing for
/// a denial.
///
/// The two halves are different questions. A denial of an absent path can only
/// remove authority, so the lexical comparison is enough. A grant of an absent
/// path has nothing to pin: the child owns the workspace, so between this
/// resolution and the backend's bind it can create that name as a symlink to
/// anywhere, and §9.1 forbids following an untrusted symlink across that
/// window. So the grant refuses as an unknown subset, naming its key path.
#[test]
fn p02_an_absent_path_refuses_as_a_grant_and_narrows_as_a_denial() {
    let workspace = Workspace::new();
    let absent = "./not-created-yet";
    assert!(
        std::fs::symlink_metadata(workspace.root.join("not-created-yet")).is_err(),
        "the path really is absent, or this test proves nothing"
    );

    // A grant refuses, with the exact key path for each kind.
    for (delta, key) in [
        (read_only(&[absent]), "jail.filesystem.read_only"),
        (read_write(&[absent]), "jail.filesystem.read_write"),
    ] {
        match workspace.resolve_project(ProfileName::Tool, |_| {}, delta) {
            Ok(_) => panic!("an absent grant target must refuse at {key}"),
            Err(error) => {
                assert_eq!(error.code, ErrorCode::PolicyWidening, "for {key}");
                assert_eq!(error.key_path.as_deref(), Some(key));
                assert_eq!(error.exit_code(), 125);
                assert!(
                    error.message.contains("unknown subset")
                        && error.message.contains("does not exist"),
                    "the refusal says which half of the rule applied: {}",
                    error.message
                );
            }
        }
    }

    // A denial of the same absent path is allowed, and lands in the snapshot.
    let resolved = workspace
        .resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                deny_read: vec![absent.as_bytes().to_vec()],
                ..PolicyDelta::default()
            },
        )
        .expect("denying an absent path only removes authority");
    assert!(
        resolved
            .snapshot
            .filesystem
            .deny_read
            .contains(&workspace.reference("not-created-yet")),
        "the denial is recorded rather than quietly dropped: {:?}",
        resolved.snapshot.filesystem.deny_read
    );

    // And once the object exists, the same grant is compared on its merits: it
    // is inside the writable workspace, so it is accepted. The refusal above
    // was about absence, not about the path.
    std::fs::create_dir(workspace.root.join("not-created-yet")).expect("create it");
    workspace
        .resolve_project(ProfileName::Tool, |_| {}, read_only(&[absent]))
        .expect("an existing path inside the writable root is an ordinary carve-out");
}

#[test]
fn p02_an_object_that_does_not_exist_is_an_unknown_subset() {
    let workspace = Workspace::new();
    let error = workspace
        .resolve_project(ProfileName::Tool, |_| {}, read_write(&["./secretsX"]))
        .expect_err("an object with no identity cannot be compared");
    assert_eq!(error.code, ErrorCode::PolicyWidening);
    assert!(
        error.message.contains("unknown subset"),
        "{}",
        error.message
    );
}

#[test]
fn p02_a_denial_is_never_a_widening_however_it_is_spelled() {
    let workspace = Workspace::new();
    // Adding a denial only removes authority, so it is not held to the
    // identity rule: a symlink or a path that does not exist is still a
    // narrowing.
    for spelling in ["./alias", "./nothing-here", "./src"] {
        workspace
            .resolve_project(
                ProfileName::Tool,
                |_| {},
                PolicyDelta {
                    deny_read: vec![spelling.as_bytes().to_vec()],
                    ..PolicyDelta::default()
                },
            )
            .unwrap_or_else(|error| panic!("denying {spelling} narrows: {error}"));
    }
}

// ---------------------------------------------------------------------------
// The rest of the §6.3 table
// ---------------------------------------------------------------------------

#[test]
fn p02_adding_a_path_grant_refuses_with_its_key_path() {
    let workspace = Workspace::new();
    // `/usr` exists on both platforms and is outside the workspace.
    expect_widening(
        workspace.resolve_project(ProfileName::Tool, |_| {}, read_write(&["/usr"])),
        "jail.filesystem.read_write",
    );
    expect_widening(
        workspace.resolve_project(
            ProfileName::Tool,
            |baseline| {
                baseline.read_only = vec![workspace.reference("vendor")];
                baseline.read_write = Vec::new();
            },
            read_write(&["./vendor"]),
        ),
        "jail.filesystem.read_write",
    );
}

#[test]
fn p02_path_prefix_confusion_refuses() {
    let workspace = Workspace::new();
    std::fs::create_dir(workspace.root.join("ab")).expect("ab");
    std::fs::create_dir_all(workspace.root.join("a/b")).expect("a/b");
    let base = |baseline: &mut ProfileBaseline| {
        baseline.read_write = vec![PathRef {
            root: RootToken::Workspace,
            path: NativeString::Text("a".to_owned()),
        }];
        baseline.deny_read = Vec::new();
    };
    // `ab` merely shares a string prefix with `a`.
    expect_widening(
        workspace.resolve_project(ProfileName::Tool, base, read_write(&["./ab"])),
        "jail.filesystem.read_write",
    );
    // A real descendant is inside the authority and is accepted.
    workspace
        .resolve_project(ProfileName::Tool, base, read_write(&["./a/b"]))
        .expect("a descendant of a writable root is not new authority");
}

#[test]
fn p02_adding_a_host_grant_refuses_and_wildcards_are_label_sets() {
    let workspace = Workspace::new();
    let agent_base = |baseline: &mut ProfileBaseline| {
        baseline.network_allow = HostRule::parse("*.example.com:443").expect("parses");
    };
    for host in ["notexample.com:443", "example.com:443", "other.net:443"] {
        expect_widening(
            workspace.resolve_project(
                ProfileName::Agent,
                agent_base,
                PolicyDelta {
                    network_allow: vec![host.to_owned()],
                    ..PolicyDelta::default()
                },
            ),
            "jail.network.allow",
        );
    }
    for host in [
        "a.example.com:443",
        "a.b.example.com:443",
        "*.a.example.com:443",
    ] {
        workspace
            .resolve_project(
                ProfileName::Agent,
                agent_base,
                PolicyDelta {
                    network_allow: vec![host.to_owned()],
                    ..PolicyDelta::default()
                },
            )
            .unwrap_or_else(|error| panic!("{host} is inside the wildcard: {error}"));
    }
}

#[test]
fn p02_a_host_the_ruleset_cannot_normalize_refuses_as_an_unknown_subset() {
    let workspace = Workspace::new();
    let error = workspace
        .resolve_project(
            ProfileName::Agent,
            |baseline| {
                baseline.network_allow = HostRule::parse("*.example.com:443").expect("parses");
            },
            PolicyDelta {
                // J3-P begin: IDNA now maps `bücher`; a malformed A-label is
                // what the ruleset still cannot normalize.
                network_allow: vec!["xn--a.example.com:443".to_owned()],
                // J3-P end
                ..PolicyDelta::default()
            },
        )
        .expect_err("an unmappable host cannot be compared");
    assert_eq!(error.code, ErrorCode::PolicyWidening);
    assert_eq!(error.key_path.as_deref(), Some("jail.network.allow"));
    assert!(
        error.message.contains("unknown subset"),
        "the message must say the relationship is unknown, got: {}",
        error.message
    );
}

#[test]
fn p02_widening_the_network_mode_refuses() {
    let workspace = Workspace::new();
    for mode in [NetworkMode::Host, NetworkMode::Proxy] {
        expect_widening(
            workspace.resolve_project(
                ProfileName::Tool,
                |_| {},
                PolicyDelta {
                    network_mode: Some(mode),
                    ..PolicyDelta::default()
                },
            ),
            "jail.network.mode",
        );
    }
}

#[test]
fn p02_raising_a_ceiling_refuses_with_that_limit_key() {
    let workspace = Workspace::new();
    expect_widening(
        workspace.resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                limits: Ceilings {
                    wall: ceiling(3_600_000, "1h"),
                    ..Ceilings::default()
                },
                ..PolicyDelta::default()
            },
        ),
        "jail.limits.wall",
    );
    expect_widening(
        workspace.resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                limits: Ceilings {
                    pids: ceiling(1024, "1024"),
                    ..Ceilings::default()
                },
                ..PolicyDelta::default()
            },
        ),
        "jail.limits.pids",
    );
}

#[test]
fn p02_weakening_coverage_evidence_or_observation_refuses() {
    let workspace = Workspace::new();
    expect_widening(
        workspace.resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                protected_coverage: Some(ProtectedCoverage::None),
                ..PolicyDelta::default()
            },
        ),
        "jail.filesystem.protected_coverage",
    );
    expect_widening(
        workspace.resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                evidence: Some(EvidenceMode::BestEffort),
                ..PolicyDelta::default()
            },
        ),
        "jail.observation.evidence",
    );
    expect_widening(
        workspace.resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                observe: Some(ObserveMode::Off),
                ..PolicyDelta::default()
            },
        ),
        "jail.observation.mode",
    );
}

#[test]
fn p02_a_project_file_may_not_select_a_profile_or_extend_one() {
    let workspace = Workspace::new();
    for key in ["profile", "extends"] {
        expect_widening(
            workspace.resolve_project(
                ProfileName::Tool,
                |_| {},
                PolicyDelta {
                    forbidden_key: Some(key.to_owned()),
                    ..PolicyDelta::default()
                },
            ),
            &format!("jail.{key}"),
        );
    }
}

// ---------------------------------------------------------------------------
// Allowed categories
// ---------------------------------------------------------------------------

#[test]
fn p02_every_narrowing_category_is_allowed() {
    let workspace = Workspace::new();

    // A read-only carve-out over a writable parent, and a further denial.
    let resolved = workspace
        .resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                read_only: vec![b"./vendor".to_vec()],
                deny_read: vec![b"./src".to_vec()],
                ..PolicyDelta::default()
            },
        )
        .expect("carve-outs and denials narrow");
    assert!(
        resolved
            .snapshot
            .filesystem
            .read_only
            .contains(&workspace.reference("vendor"))
    );

    // A lower ceiling, and a previously absent one that becomes required.
    let resolved = workspace
        .resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                limits: Ceilings {
                    wall: ceiling(60_000, "1m"),
                    mem: ceiling(512 * 1024 * 1024, "512MiB"),
                    ..Ceilings::default()
                },
                ..PolicyDelta::default()
            },
        )
        .expect("lowering and adding ceilings narrows");
    assert_eq!(
        resolved
            .snapshot
            .limits
            .wall
            .as_ref()
            .map(|limit| limit.value.clone()),
        Some("60000".to_owned())
    );
    assert_eq!(
        resolved
            .snapshot
            .limits
            .mem
            .as_ref()
            .map(|limit| limit.required),
        Some(true),
        "a previously absent finite limit becomes required"
    );

    // Proxy narrowed to none, and its former grants dropped from the digest.
    let resolved = workspace
        .resolve_project(
            ProfileName::Agent,
            |baseline| {
                baseline.network_allow = HostRule::parse("*.example.com:443").expect("parses");
            },
            PolicyDelta {
                network_mode: Some(NetworkMode::None),
                ..PolicyDelta::default()
            },
        )
        .expect("proxy narrows to none");
    assert_eq!(resolved.snapshot.network.mode, "none");
    assert!(resolved.snapshot.network.allow.is_empty());
    assert_eq!(resolved.snapshot.network.ruleset, None);

    // Observation enabled and evidence strengthened.
    let resolved = workspace
        .resolve_project(
            ProfileName::Tool,
            |baseline| {
                baseline.observation.mode = ObserveMode::Off;
                baseline.observation.evidence = EvidenceMode::BestEffort;
            },
            PolicyDelta {
                observe: Some(ObserveMode::On),
                evidence: Some(EvidenceMode::Strict),
                ..PolicyDelta::default()
            },
        )
        .expect("stronger observation narrows");
    assert_eq!(resolved.snapshot.observation.mode, ObserveMode::On);
    assert_eq!(resolved.snapshot.observation.evidence, EvidenceMode::Strict);

    // Stronger coverage is allowed at resolution; the capability check is what
    // refuses when the platform cannot provide it.
    let resolved = workspace
        .resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                protected_coverage: Some(ProtectedCoverage::AllDescendants),
                ..PolicyDelta::default()
            },
        )
        .expect("stronger coverage narrows");
    assert_eq!(
        resolved.snapshot.filesystem.protected_coverage,
        ProtectedCoverage::AllDescendants
    );
    assert!(
        resolved
            .requirements
            .iter()
            .any(|requirement| requirement == "protected_coverage:all_descendants")
    );
}

#[test]
fn p02_a_trusted_operator_layer_may_still_grant_and_is_recorded() {
    let workspace = Workspace::new();
    // §6.3's table governs narrowing files. The operator's own command line is
    // a trusted input and adds authority; only the project file narrows. The
    // grant is recorded in the receipt (§13.2, A2).
    let mut baseline = profiles::baseline(ProfileName::Tool, Os::Linux, &|_| None);
    baseline.read_only = Vec::new();
    baseline.read_write = vec![workspace.reference("")];
    let inputs = ResolveInputs {
        platform: Os::Linux,
        base_profile: ProfileName::Tool,
        policy_name: "tool".to_owned(),
        baseline,
        workspace: workspace.bytes(),
        scratch: ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers: vec![Layer {
            origin: LayerOrigin::CommandLine,
            base_dir: Some(workspace.bytes()),
            key_prefix: String::new(),
            narrowing: false,
            delta: read_write(&["/usr"]),
        }],
    };
    let resolved = ouro_jail::policy::resolve(&inputs).expect("the operator may grant");
    assert!(
        resolved
            .snapshot
            .filesystem
            .read_write
            .contains(&PathRef::host(NativeString::Text("/usr".to_owned())))
    );
    assert_eq!(resolved.grants.len(), 1, "the grant is recorded");
    assert_eq!(resolved.grants[0].kind, "read_write");
    assert_eq!(resolved.grants[0].by, "operator");
    assert_eq!(
        resolved.grants[0].value,
        NativeString::Text("/usr".to_owned())
    );

    // The baseline is not a grant: a run with no operator flags records none.
    let mut plain = profiles::baseline(ProfileName::Tool, Os::Linux, &|_| None);
    plain.read_only = Vec::new();
    plain.read_write = vec![workspace.reference("")];
    let plain_inputs = ResolveInputs {
        baseline: plain,
        layers: Vec::new(),
        ..inputs
    };
    let resolved = ouro_jail::policy::resolve(&plain_inputs).expect("resolves");
    assert!(
        resolved.grants.is_empty(),
        "the profile baseline is not a grant"
    );
}

#[test]
fn p02_a_trusted_layer_is_not_held_to_the_identity_rule() {
    let workspace = Workspace::new();
    // The operator may point `--ro` at a symlink they control: §2 trusts the
    // operator's own command line. Only the workspace's own file is untrusted.
    let mut baseline = profiles::baseline(ProfileName::Tool, Os::Linux, &|_| None);
    baseline.read_only = Vec::new();
    baseline.read_write = vec![workspace.reference("")];
    let inputs = ResolveInputs {
        platform: Os::Linux,
        base_profile: ProfileName::Tool,
        policy_name: "tool".to_owned(),
        baseline,
        workspace: workspace.bytes(),
        scratch: ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers: vec![Layer {
            origin: LayerOrigin::CommandLine,
            base_dir: Some(workspace.bytes()),
            key_prefix: String::new(),
            narrowing: false,
            delta: read_only(&["./alias"]),
        }],
    };
    ouro_jail::policy::resolve(&inputs).expect("an operator grant may name a symlink");
}

/// §6.2: "Only operator files expand a leading `~/` against the operator
/// home"; CLI paths are relative to the invocation cwd. So `--rw '~/x'` must
/// reach the resolver as the literal name `~/x` beneath the cwd, even though
/// the operator home is known — not as a grant on the operator's home
/// directory, which the operator never asked to expose.
#[test]
fn a_cli_tilde_path_is_cwd_relative_not_home_relative() {
    let workspace = Workspace::new();
    let mut baseline = profiles::baseline(ProfileName::Tool, Os::Linux, &|_| None);
    baseline.read_only = Vec::new();
    baseline.read_write = vec![workspace.reference("")];
    let cwd = workspace.bytes();
    let home: &[u8] = b"/home/operator";
    let inputs = ResolveInputs {
        platform: Os::Linux,
        base_profile: ProfileName::Tool,
        policy_name: "tool".to_owned(),
        baseline,
        workspace: cwd.clone(),
        scratch: ScratchRoot::Managed,
        vendor_state: None,
        operator_home: Some(home.to_vec()),
        translation_prefixes: Vec::new(),
        layers: vec![Layer {
            origin: LayerOrigin::CommandLine,
            base_dir: Some(cwd),
            key_prefix: String::new(),
            narrowing: false,
            delta: read_write(&["~/x"]),
        }],
    };
    let resolved = ouro_jail::policy::resolve(&inputs).expect("the operator may grant");
    let granted: Vec<&[u8]> = resolved
        .grants
        .iter()
        .map(|grant| grant.value.as_bytes())
        .collect();
    let mut anchored = workspace.bytes();
    anchored.push(b'/');
    anchored.extend_from_slice(b"~/x");
    let mut escaped = home.to_vec();
    escaped.push(b'/');
    escaped.extend_from_slice(b"x");
    assert!(
        granted.contains(&anchored.as_slice()),
        "`~/x` resolves against the cwd: {granted:?}"
    );
    assert!(
        !granted.contains(&escaped.as_slice()),
        "the operator home is never substituted: {granted:?}"
    );
}

#[test]
fn p02_the_workspace_root_itself_is_a_real_directory() {
    // A guard for the harness: if the workspace stopped existing, every test
    // above would pass for the wrong reason.
    let workspace = Workspace::new();
    assert!(Path::new(&workspace.root).is_dir());
    assert!(workspace.root.join("secrets").is_dir());
    assert!(
        std::fs::symlink_metadata(workspace.root.join("alias"))
            .expect("alias")
            .file_type()
            .is_symlink()
    );
}
