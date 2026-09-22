//! P02: every widening category of the §6.3 table refuses with the exact key
//! path, and every narrowing category is allowed.
//!
//! The narrowing layer here is a workspace-root `ouro.toml`, so the reported
//! key paths carry the `jail.` prefix that a project file uses. Path-prefix and
//! host-wildcard confusion get their own cases: `/work/a` is not an ancestor of
//! `/work/ab`, and `*.example.com` covers neither the apex nor `notexample.com`.

use ouro_jail::network::{HostRule, NetworkMode};
use ouro_jail::policy::{
    Ceiling, Ceilings, Layer, LayerOrigin, PathRef, PolicyDelta, ProfileBaseline, ProfileName,
    ProtectedCoverage, ResolveInputs, Resolved, RootToken, ScratchRoot,
};
use ouro_jail::profiles;
use ouro_jail::records::{ErrorCode, EvidenceMode, JailError, NativeString, ObserveMode, Os};

const WORKSPACE: &[u8] = b"/work";

fn workspace_ref(path: &str) -> PathRef {
    PathRef {
        root: RootToken::Workspace,
        path: NativeString::Text(path.to_owned()),
    }
}

/// Resolves `tool` (or `agent`) with a project layer carrying `delta`.
fn resolve_project(
    profile: ProfileName,
    tweak: impl FnOnce(&mut ProfileBaseline),
    delta: PolicyDelta,
) -> Result<Resolved, JailError> {
    let mut baseline = profiles::baseline(profile, Os::Linux, &|_| None);
    // A deterministic baseline: no host runtime roots, one writable workspace.
    baseline.read_only = Vec::new();
    baseline.read_write = vec![workspace_ref("")];
    tweak(&mut baseline);
    let inputs = ResolveInputs {
        platform: Os::Linux,
        base_profile: profile,
        policy_name: profile.as_str().to_owned(),
        baseline,
        workspace: WORKSPACE.to_vec(),
        scratch: ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers: vec![Layer {
            origin: LayerOrigin::ProjectConfig("ouro.toml".to_owned()),
            base_dir: Some(WORKSPACE.to_vec()),
            key_prefix: "jail.".to_owned(),
            narrowing: true,
            delta,
        }],
    };
    ouro_jail::policy::resolve(&inputs)
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

// ---------------------------------------------------------------------------
// Refusing categories
// ---------------------------------------------------------------------------

#[test]
fn p02_adding_a_path_grant_refuses_with_its_key_path() {
    expect_widening(
        resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                read_write: vec![b"/elsewhere".to_vec()],
                ..PolicyDelta::default()
            },
        ),
        "jail.filesystem.read_write",
    );
    expect_widening(
        resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                read_only: vec![b"/etc".to_vec()],
                ..PolicyDelta::default()
            },
        ),
        "jail.filesystem.read_only",
    );
}

#[test]
fn p02_path_prefix_confusion_refuses() {
    let base = |baseline: &mut ProfileBaseline| {
        baseline.read_write = vec![workspace_ref("a")];
    };
    // `/work/ab` merely shares a string prefix with `/work/a`.
    expect_widening(
        resolve_project(
            ProfileName::Tool,
            base,
            PolicyDelta {
                read_write: vec![b"ab".to_vec()],
                ..PolicyDelta::default()
            },
        ),
        "jail.filesystem.read_write",
    );
    // A real descendant is inside the authority and is accepted.
    resolve_project(
        ProfileName::Tool,
        base,
        PolicyDelta {
            read_write: vec![b"a/b".to_vec()],
            ..PolicyDelta::default()
        },
    )
    .expect("a descendant of a writable root is not new authority");
}

#[test]
fn p02_adding_a_host_grant_refuses_and_wildcards_are_label_sets() {
    let agent_base = |baseline: &mut ProfileBaseline| {
        baseline.network_allow = HostRule::parse("*.example.com:443").expect("parses");
    };
    for host in ["notexample.com:443", "example.com:443", "other.net:443"] {
        expect_widening(
            resolve_project(
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
        resolve_project(
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
    let agent_base = |baseline: &mut ProfileBaseline| {
        baseline.network_allow = HostRule::parse("*.example.com:443").expect("parses");
    };
    let error = resolve_project(
        ProfileName::Agent,
        agent_base,
        PolicyDelta {
            network_allow: vec!["bücher.example.com:443".to_owned()],
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
    expect_widening(
        resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                network_mode: Some(NetworkMode::Host),
                ..PolicyDelta::default()
            },
        ),
        "jail.network.mode",
    );
    expect_widening(
        resolve_project(
            ProfileName::Tool,
            |_| {},
            PolicyDelta {
                network_mode: Some(NetworkMode::Proxy),
                ..PolicyDelta::default()
            },
        ),
        "jail.network.mode",
    );
}

#[test]
fn p02_raising_a_ceiling_refuses_with_that_limit_key() {
    expect_widening(
        resolve_project(
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
        resolve_project(
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
    expect_widening(
        resolve_project(
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
        resolve_project(
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
        resolve_project(
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
    for key in ["profile", "extends"] {
        expect_widening(
            resolve_project(
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
    // A read-only carve-out over a writable parent.
    let resolved = resolve_project(
        ProfileName::Tool,
        |_| {},
        PolicyDelta {
            read_only: vec![b"vendor".to_vec()],
            deny_read: vec![b"secrets".to_vec(), b"/outside".to_vec()],
            ..PolicyDelta::default()
        },
    )
    .expect("carve-outs and denials narrow");
    assert!(
        resolved
            .snapshot
            .filesystem
            .read_only
            .contains(&workspace_ref("vendor"))
    );
    assert_eq!(resolved.snapshot.filesystem.deny_read.len(), 2);

    // A lower ceiling, and a previously absent one that becomes required.
    let resolved = resolve_project(
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
            .map(|c| c.value.clone()),
        Some("60000".to_owned())
    );
    assert_eq!(
        resolved.snapshot.limits.mem.as_ref().map(|c| c.required),
        Some(true),
        "a previously absent finite limit becomes required"
    );

    // Proxy narrowed to none, and a shrunk allow set.
    let resolved = resolve_project(
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
    assert!(
        resolved.snapshot.network.allow.is_empty(),
        "a non-proxy policy carries no host grants into the digest"
    );
    assert_eq!(resolved.snapshot.network.ruleset, None);

    // Observation enabled and evidence strengthened.
    let resolved = resolve_project(
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
    let resolved = resolve_project(
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
            .any(|requirement| requirement == "protected_coverage:all_descendants"),
        "the stronger coverage becomes a requirement to be measured"
    );
}

#[test]
fn p02_a_trusted_operator_layer_may_still_grant() {
    // The §6.3 table governs narrowing files. The operator's own command line
    // is a trusted input and adds authority; only the project file narrows.
    let mut baseline = profiles::baseline(ProfileName::Tool, Os::Linux, &|_| None);
    baseline.read_only = Vec::new();
    baseline.read_write = vec![workspace_ref("")];
    let inputs = ResolveInputs {
        platform: Os::Linux,
        base_profile: ProfileName::Tool,
        policy_name: "tool".to_owned(),
        baseline,
        workspace: WORKSPACE.to_vec(),
        scratch: ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers: vec![Layer {
            origin: LayerOrigin::CommandLine,
            base_dir: Some(WORKSPACE.to_vec()),
            key_prefix: String::new(),
            narrowing: false,
            delta: PolicyDelta {
                read_write: vec![b"/elsewhere".to_vec()],
                ..PolicyDelta::default()
            },
        }],
    };
    let resolved = ouro_jail::policy::resolve(&inputs).expect("the operator may grant");
    assert!(
        resolved
            .snapshot
            .filesystem
            .read_write
            .contains(&PathRef::host(NativeString::Text("/elsewhere".to_owned())))
    );
}
