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

use ouro_jail::cli::PolicyArgs;
use ouro_jail::config::EnvSettings;
use ouro_jail::network::{HostRule, NetworkMode};
use ouro_jail::policy::{
    Ceiling, Ceilings, Layer, LayerOrigin, PathRef, PolicyDelta, ProfileBaseline, ProfileName,
    ProtectedCoverage, ResolveInputs, Resolved, RootToken, ScratchRoot,
};
use ouro_jail::profiles;
use ouro_jail::records::{ErrorCode, EvidenceMode, JailError, NativeString, ObserveMode, Os};
use ouro_jail::supervisor;

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

// J5-B1 begin: P02 — mem/cpu ceilings and launch/executable/backend keys
/// Raising the `mem` or `cpu` ceiling refuses with that limit's key path.
/// The §6.3 battery raised only `wall` and `pids`; a baseline that already
/// carries a `mem` and a `cpu` ceiling is needed, because adding a
/// previously absent finite limit is a narrowing, not a widening
/// (gap analysis §1.2, P02).
#[test]
fn p02_raising_mem_or_cpu_refuses_with_that_limit_key() {
    let workspace = Workspace::new();
    let with_ceiling = |mem: bool, value: u64| {
        move |baseline: &mut ProfileBaseline| {
            let ceiling = Ceiling {
                value,
                requested: value.to_string(),
                required: true,
            };
            if mem {
                baseline.limits.mem = Some(ceiling);
            } else {
                baseline.limits.cpu = Some(ceiling);
            }
        }
    };
    // The baseline caps memory at 256 MiB; the project asks for 512 MiB.
    expect_widening(
        workspace.resolve_project(
            ProfileName::Build,
            with_ceiling(true, 256 * 1024 * 1024),
            PolicyDelta {
                limits: Ceilings {
                    mem: ceiling(512 * 1024 * 1024, "512MiB"),
                    ..Ceilings::default()
                },
                ..PolicyDelta::default()
            },
        ),
        "jail.limits.mem",
    );
    // The baseline caps CPU at 50%; the project asks for 100%.
    expect_widening(
        workspace.resolve_project(
            ProfileName::Tool,
            with_ceiling(false, 50),
            PolicyDelta {
                limits: Ceilings {
                    cpu: ceiling(100, "100"),
                    ..Ceilings::default()
                },
                ..PolicyDelta::default()
            },
        ),
        "jail.limits.cpu",
    );
}

/// A project `ouro.toml` cannot add credentials, select a launch profile, name
/// an executable or set a backend: each is refused (§6.3's "Add credentials,
/// launch profile, executable, `none` or backend settings | Refuse"). These
/// are not narrowing keys at all, so the workspace-owned file is rejected
/// rather than silently ignored, and the refusal names the offending key.
#[test]
fn p02_a_project_file_cannot_add_credentials_launch_executable_or_backend() {
    for (label, body) in [
        (
            "credentials",
            "[jail.credentials.token]\nsource = \"/etc/passwd\"\ndest = \"t\"\n",
        ),
        ("launch", "[jail]\nlaunch = \"vendor\"\n"),
        ("executable", "[jail]\nexecutable = \"/bin/sh\"\n"),
        ("backend", "[jail.backend]\ncommand = \"bwrap\"\n"),
    ] {
        let error = ouro_jail::config::parse_project_config(body)
            .expect_err(&format!("a project file adding {label} must refuse"));
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{label}: {error:?}");
        // The refusal is not silently swallowed and does not exit 0.
        assert_eq!(
            error.exit_code(),
            2,
            "{label}: a config syntax error exits 2"
        );
        assert!(
            error.message.to_lowercase().contains(label)
                || error.message.to_lowercase().contains("unknown"),
            "{label}: the refusal does not name the offending key: {}",
            error.message
        );
    }
}
// J5-B1 end

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

// J5-B1 begin: the real file layers, through supervisor::resolve_plan
// (P01.6, P02.6, P02.9, P02.10, P02.13, I02.4)

/// An operator config directory, a private state root and a workspace, and
/// the real resolution path the `run` command takes (`resolve_plan`): files
/// parsed by the product, layered by the product, refused by the product.
struct Files {
    _temp: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    workspace: PathBuf,
}

impl Files {
    fn new() -> Files {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = common::private_tempdir();
        let root = std::fs::canonicalize(temp.path()).expect("canonical");
        let config = root.join("config");
        let workspace = root.join("workspace");
        for dir in [
            &config,
            &root.join("data"),
            &workspace,
            &config.join("launch"),
        ] {
            std::fs::create_dir_all(dir).expect("a directory");
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).expect("private");
        }
        Files {
            _temp: temp,
            root,
            config,
            workspace,
        }
    }

    fn write(&self, path: &Path, text: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, text).expect("a file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("0600");
    }

    fn project(&self, text: &str) {
        self.write(&self.workspace.join("ouro.toml"), text);
    }

    fn launch(&self, name: &str, text: &str) {
        self.write(
            &self.config.join("launch").join(format!("{name}.toml")),
            text,
        );
    }

    fn args(&self, profile: &str) -> PolicyArgs {
        PolicyArgs {
            profile: Some(profile.to_owned()),
            workspace: Some(self.workspace.clone()),
            ..PolicyArgs::default()
        }
    }

    fn plan(&self, args: &PolicyArgs) -> Result<supervisor::Plan, JailError> {
        let ctx = supervisor::Context {
            platform: Box::new(ouro_jail::platform::Unimplemented),
            env_settings: EnvSettings {
                config_dir: Some(self.config.clone()),
                data_dir: Some(self.root.join("data")),
                ..EnvSettings::default()
            },
            cwd: self.workspace.clone(),
            home: Some(self.root.join("home")),
            env_lookup: Box::new(|_| None),
        };
        supervisor::resolve_plan(&ctx, args)
    }

    fn digest(&self, args: &PolicyArgs) -> String {
        match self.plan(args) {
            Ok(plan) => plan.resolved.digest,
            Err(error) => panic!("the files must resolve: {error:?}"),
        }
    }
}

/// The refusal a resolution must produce, with its code and exact key path.
fn refuses(result: Result<supervisor::Plan, JailError>, code: ErrorCode, key: &str) -> JailError {
    match result {
        Ok(_) => panic!("expected a {code:?} refusal naming `{key}`"),
        Err(error) => {
            assert_eq!(error.code, code, "{error:?}");
            assert_eq!(error.key_path.as_deref(), Some(key), "{error:?}");
            error
        }
    }
}

/// P02.6 through the files: the operator's `config.toml` caps memory and CPU;
/// a project `ouro.toml` raising either refuses with that limit's key path.
#[test]
fn p02_raising_mem_or_cpu_through_the_project_file_refuses_with_the_limit_key() {
    let files = Files::new();
    files.write(
        &files.config.join("config.toml"),
        "[jail.limits]\nmem = \"256MiB\"\ncpu = 50\n",
    );
    files.project("[jail.limits]\nmem = \"512MiB\"\n");
    refuses(
        files.plan(&files.args("tool")),
        ErrorCode::PolicyWidening,
        "jail.limits.mem",
    );
    files.project("[jail.limits]\ncpu = 100\n");
    refuses(
        files.plan(&files.args("tool")),
        ErrorCode::PolicyWidening,
        "jail.limits.cpu",
    );
    // Lowering either is a narrowing, so the refusals are about the raise.
    files.project("[jail.limits]\nmem = \"128MiB\"\ncpu = 25\n");
    assert!(files.plan(&files.args("tool")).is_ok());
}

/// P02.9: a project `ouro.toml` cannot add a credential. Credentials are a
/// real key of one layer, the operator's launch profile (§12); in the
/// workspace-owned narrowing file they are a widening (§6.3 "Add credentials
/// ... Refuse"), refused with their exact key path rather than as a typo.
#[test]
fn p02_a_credential_in_the_project_file_refuses_with_its_key_path() {
    let files = Files::new();
    files.project(
        "[jail.credentials.token]\nsource = \"/etc/hostname\"\ndest = \"token\"\nmode = \"copy_rw\"\n",
    );
    refuses(
        files.plan(&files.args("agent")),
        ErrorCode::PolicyWidening,
        "jail.credentials",
    );
}

/// P02.10: widening through a launch profile's own settings refuses with the
/// key path of the setting: credentials or proxy hosts under a profile that
/// rejects them, and any launch profile under `none` (§6.1).
#[test]
fn p02_widening_through_a_launch_profile_refuses_with_its_key_path() {
    let files = Files::new();
    let source = files.root.join("fixture-credential");
    files.write(&source, "not a real credential\n");
    files.launch(
        "creds",
        &format!(
            "name = \"creds\"\njail = \"agent\"\n[credentials.token]\nsource = {:?}\ndest = \"token\"\nmode = \"copy_rw\"\n",
            source.display().to_string()
        ),
    );
    files.launch(
        "hosts",
        "name = \"hosts\"\njail = \"agent\"\n[network]\nallow = [\"example.test:443\"]\n",
    );
    files.launch("plain", "name = \"plain\"\njail = \"tool\"\n");
    let with = |profile: &str, launch: &str| PolicyArgs {
        launch: Some(launch.to_owned()),
        ..files.args(profile)
    };
    refuses(
        files.plan(&with("tool", "creds")),
        ErrorCode::InvalidConfig,
        "launch.credentials",
    );
    refuses(
        files.plan(&with("tool", "hosts")),
        ErrorCode::InvalidConfig,
        "launch.network.allow",
    );
    refuses(
        files.plan(&with("none", "plain")),
        ErrorCode::PolicyWidening,
        "--launch",
    );
    // The same files are accepted where the profile permits them.
    assert!(files.plan(&with("agent", "creds")).is_ok());
    assert!(files.plan(&with("agent", "hosts")).is_ok());
    assert!(files.plan(&with("tool", "plain")).is_ok());
}

/// P02.13: `none` cannot be selected through an untrusted layer — neither a
/// project file naming it nor an operator profile file extending it (§6.1:
/// `--profile none` is the only way).
#[test]
fn p02_none_cannot_be_selected_through_a_project_or_profile_file() {
    let files = Files::new();
    files.project("[jail]\nprofile = \"none\"\n");
    refuses(
        files.plan(&files.args("tool")),
        ErrorCode::PolicyWidening,
        "jail.profile",
    );
    std::fs::remove_file(files.workspace.join("ouro.toml")).expect("removed");
    let profile = files.workspace.join("widen.toml");
    files.write(
        &profile,
        "schema = \"ouro.jail.policy/1\"\nextends = \"none\"\n",
    );
    refuses(
        files.plan(&files.args(profile.to_str().expect("UTF-8"))),
        ErrorCode::PolicyWidening,
        "extends",
    );
}

/// P01.6: a semantic change in a canonical TOML input changes the policy
/// digest, through the files the product parses: the canonical operator
/// profile (a limit, a grant) and a launch profile (an environment value).
/// A change of form only (comments, blank lines, key order) does not, and the
/// argv digest, the other digest of an attempt, never moves with the policy.
#[test]
fn p01_a_semantic_change_in_a_canonical_toml_input_changes_only_the_policy_digest() {
    let files = Files::new();
    for dir in ["fixtures", "secrets", "other"] {
        std::fs::create_dir(files.workspace.join(dir)).expect("a directory");
    }
    let canonical = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/specs/jail-v1/fixtures/canonical-input.toml"),
    )
    .expect("the canonical input");
    let profile = files.workspace.join("canonical.toml");
    let launch = |value: &str| {
        files.launch(
            "fx",
            &format!("name = \"fx\"\njail = \"tool\"\n[environment]\nFIXTURE_VALUE = {value:?}\n"),
        );
    };
    let args = PolicyArgs {
        launch: Some("fx".to_owned()),
        ..files.args(profile.to_str().expect("UTF-8"))
    };
    let argv: Vec<Vec<u8>> = vec![b"/usr/bin/true".to_vec()];
    let argv_digest = ouro_jail::canonical::argv_digest(&argv);

    let digest_of = |text: &str, value: &str| {
        files.write(&profile, text);
        launch(value);
        files.digest(&args)
    };
    let base = digest_of(&canonical, "one");
    let limit = digest_of(&canonical.replace("wall = \"5m\"", "wall = \"4m\""), "one");
    let grant = digest_of(&canonical.replace("\"./fixtures\"", "\"./other\""), "one");
    let environment = digest_of(&canonical, "two");
    let form = digest_of(
        &format!(
            "# a comment\n\n{}\n",
            canonical.replace("pids = 64\n", "pids = 64\n\n")
        ),
        "one",
    );
    assert_ne!(limit, base, "a changed limit kept the digest");
    assert_ne!(grant, base, "a changed grant kept the digest");
    assert_ne!(
        environment, base,
        "a changed environment value kept the digest"
    );
    assert_ne!(limit, grant);
    assert_ne!(grant, environment);
    assert_eq!(form, base, "a change of form only moved the digest");
    // The attempt's other digest is a function of its argv alone.
    assert_eq!(ouro_jail::canonical::argv_digest(&argv), argv_digest);
}

/// I02.4: `--launch NAME` reads only `<operator config>/launch/NAME.toml`.
/// With no such file it refuses, even with the same name planted in the
/// workspace, in a `profiles/launch/` directory beside it and in the default
/// configuration under the operator home; there is no built-in fallback to
/// the bundled profiles. The operator's own file is then what resolves.
#[test]
fn i02_launch_reads_only_the_operators_configuration() {
    let files = Files::new();
    let bundled = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles/launch/opencode.toml"),
    )
    .expect("the bundled opencode profile");
    for decoy in [
        files.workspace.join("launch"),
        files.workspace.join("profiles/launch"),
        files.root.join("home/.config/ouro/launch"),
    ] {
        std::fs::create_dir_all(&decoy).expect("a decoy directory");
        files.write(&decoy.join("opencode.toml"), &bundled);
    }
    let args = PolicyArgs {
        launch: Some("opencode".to_owned()),
        ..PolicyArgs {
            workspace: Some(files.workspace.clone()),
            ..PolicyArgs::default()
        }
    };
    let error = refuses(files.plan(&args), ErrorCode::InvalidConfig, "--launch");
    assert!(
        error
            .message
            .contains(&files.config.join("launch").display().to_string()),
        "the refusal names the operator's launch directory: {}",
        error.message
    );
    files.launch("opencode", &bundled);
    let plan = files.plan(&args).expect("the operator's own file resolves");
    assert_eq!(plan.config_dir, files.config);
}
// J5-B1 end

// J5-B1 begin: P02.12
/// P02.12: a symlink component and a case variation of a denied subtree
/// refuse as a widening with the exact key path of the grant that tried
/// them, for both grant keys a narrowing file has. (P02.11 proves the
/// refusal; this proves the key path the operator is pointed at.)
#[test]
fn p02_a_symlink_component_and_a_case_variation_refuse_with_the_key_path() {
    let workspace = Workspace::new();
    for (key, delta) in [
        (
            "jail.filesystem.read_only",
            read_only as fn(&[&str]) -> PolicyDelta,
        ),
        ("jail.filesystem.read_write", read_write),
    ] {
        for spelling in ["./alias", "./escape", "./alias/deeper", "./SECRETS"] {
            let error = workspace
                .resolve_project(ProfileName::Tool, |_| {}, delta(&[spelling]))
                .expect_err("a symlink or a case variation must not become a grant");
            assert_eq!(error.code, ErrorCode::PolicyWidening, "{key} {spelling}");
            assert_eq!(
                error.key_path.as_deref(),
                Some(key),
                "{spelling}: the refusal names the grant's key path"
            );
        }
    }
}
// J5-B1 end
