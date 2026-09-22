//! The built-in profile baselines.
//!
//! Implements north star §4.2 (profile table) and jail-v1 §6.4 (the
//! authoritative defaults table). The baseline is data in this one module, not
//! scattered through the resolver, so that a change to a default is a change to
//! one table.
//!
//! The Linux runtime roots are declared here as data. Resolving distribution
//! symlinks (`/bin` into `/usr/bin`) and expanding `/lib*` are filesystem acts
//! that belong to the Linux platform slice at preparation (§9.1); portable code
//! states the requested roots and claims nothing about how they resolve.

use crate::network::NetworkMode;
use crate::policy::ObservationSnapshot;
use crate::policy::{
    Ceiling, Ceilings, EnvBinding, EnvValue, PathRef, ProfileBaseline, ProfileName,
    ProtectedCoverage, RootToken,
};
use crate::records::{EvidenceMode, NativeString, ObserveMode, Os};

/// The initial Linux runtime roots for a contained profile (§9.1).
///
/// `/lib*` is written out as the two names the reference host has; the Linux
/// slice expands the glob against the real filesystem and records the mounts it
/// actually made.
pub const LINUX_RUNTIME_ROOTS: &[&str] = &[
    "/usr",
    "/bin",
    "/lib",
    "/lib64",
    "/etc/ssl",
    "/etc/resolv.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/localtime",
];

/// Reads one environment variable as native bytes.
///
/// A parameter rather than a direct `std::env` call so that a test can resolve
/// a deterministic baseline without the machine's environment reaching a digest.
pub type EnvLookup = dyn Fn(&str) -> Option<Vec<u8>>;

/// The protected path segments `tool` denies beneath a writable root (§4.4).
pub const PROTECTED_SEGMENTS: &[&str] = &[".git", ".ouroboros"];

/// Environment names a contained profile admits from the operator's
/// environment (§12). Values are read from the supervisor's environment; the
/// receipt records only the names.
pub const CONTAINED_ENVIRONMENT_NAMES: &[&str] = &["LANG", "TERM", "TZ"];

/// The `PATH` a contained profile gives its child (§6.1).
///
/// A fixed value over the runtime roots the profile grants, never the
/// supervisor's own. The operator's `PATH` names their home, their toolchain
/// managers and whatever else they have installed; handing it to the child
/// discloses all of that and points it at directories the jail does not grant,
/// so every lookup through it would miss anyway.
pub const CONTAINED_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Builds the baseline a built-in profile expands to.
///
/// `lookup` reads the supervisor's environment for the admitted names. It is a
/// parameter so that a test can resolve a deterministic baseline without the
/// machine's environment leaking into a digest.
#[must_use]
pub fn baseline(profile: ProfileName, platform: Os, lookup: &EnvLookup) -> ProfileBaseline {
    let runtime_roots: Vec<PathRef> = match platform {
        // macOS execution is unsupported in this milestone (§3.2), so no native
        // runtime root is claimed for it. An empty list is the honest baseline.
        Os::Macos => Vec::new(),
        Os::Linux => LINUX_RUNTIME_ROOTS
            .iter()
            .map(|path| PathRef::host(NativeString::Text((*path).to_owned())))
            .collect(),
    };
    let workspace_root = PathRef {
        root: RootToken::Workspace,
        path: NativeString::Text(String::new()),
    };
    let scratch_root = PathRef {
        root: RootToken::Scratch,
        path: NativeString::Text(String::new()),
    };
    let vendor_root = PathRef {
        root: RootToken::VendorState,
        path: NativeString::Text(String::new()),
    };

    let observation = ObservationSnapshot {
        mode: ObserveMode::On,
        evidence: EvidenceMode::Strict,
    };

    match profile {
        ProfileName::Agent => ProfileBaseline {
            read_write: vec![workspace_root, scratch_root, vendor_root],
            read_only: runtime_roots,
            deny_read: Vec::new(),
            protected_segments: Vec::new(),
            protected_coverage: ProtectedCoverage::None,
            network_mode: NetworkMode::Proxy,
            network_allow: Vec::new(),
            limits: Ceilings {
                wall: Some(required("2h", 2 * 60 * 60 * 1000)),
                pids: Some(preferred("512", 512)),
                mem: None,
                cpu: None,
            },
            observation,
            environment: contained_environment(lookup),
        },
        ProfileName::Tool => ProfileBaseline {
            read_write: vec![workspace_root, scratch_root],
            read_only: runtime_roots,
            deny_read: Vec::new(),
            protected_segments: PROTECTED_SEGMENTS
                .iter()
                .map(|segment| (*segment).to_owned())
                .collect(),
            protected_coverage: ProtectedCoverage::ExistingAndRoot,
            network_mode: NetworkMode::None,
            network_allow: Vec::new(),
            limits: Ceilings {
                wall: Some(required("30m", 30 * 60 * 1000)),
                pids: Some(preferred("256", 256)),
                mem: None,
                cpu: None,
            },
            observation,
            environment: contained_environment(lookup),
        },
        ProfileName::Build => ProfileBaseline {
            read_write: vec![scratch_root],
            read_only: runtime_roots,
            deny_read: Vec::new(),
            protected_segments: Vec::new(),
            protected_coverage: ProtectedCoverage::None,
            network_mode: NetworkMode::None,
            network_allow: Vec::new(),
            limits: Ceilings {
                wall: Some(required("1h", 60 * 60 * 1000)),
                pids: Some(preferred("512", 512)),
                // §6.4: `build` requires an explicit memory ceiling. The
                // baseline leaves it absent so that resolving `build` without
                // one refuses rather than inventing a number.
                mem: None,
                cpu: None,
            },
            observation,
            environment: contained_environment(lookup),
        },
        ProfileName::None => ProfileBaseline {
            read_write: Vec::new(),
            read_only: Vec::new(),
            deny_read: Vec::new(),
            protected_segments: Vec::new(),
            protected_coverage: ProtectedCoverage::None,
            network_mode: NetworkMode::Host,
            network_allow: Vec::new(),
            limits: Ceilings {
                wall: Some(required("2h", 2 * 60 * 60 * 1000)),
                pids: None,
                mem: None,
                cpu: None,
            },
            observation,
            environment: crate::policy::EnvironmentSnapshot {
                // §12: `none` inherits the host environment except reserved
                // Ouroboros names, and records only explicit overrides.
                inherit_host: true,
                bindings: Vec::new(),
            },
        },
    }
}

fn required(requested: &str, value: u64) -> Ceiling {
    Ceiling {
        value,
        requested: requested.to_owned(),
        required: true,
    }
}

fn preferred(requested: &str, value: u64) -> Ceiling {
    Ceiling {
        value,
        requested: requested.to_owned(),
        required: false,
    }
}

/// The contained environment: an empty environment plus the admitted names that
/// the operator's environment actually defines, plus the generated `TMPDIR`.
fn contained_environment(lookup: &EnvLookup) -> crate::policy::EnvironmentSnapshot {
    let mut bindings = vec![EnvBinding {
        name: "PATH".to_owned(),
        value: EnvValue::Native(NativeString::Text(CONTAINED_PATH.to_owned())),
    }];
    for name in CONTAINED_ENVIRONMENT_NAMES {
        if let Some(value) = lookup(name)
            && let Ok(value) = NativeString::from_bytes(value)
        {
            bindings.push(EnvBinding {
                name: (*name).to_owned(),
                value: EnvValue::Native(value),
            });
        }
    }
    bindings.push(EnvBinding {
        name: "TMPDIR".to_owned(),
        value: EnvValue::Path(PathRef {
            root: RootToken::Scratch,
            path: NativeString::Text(String::new()),
        }),
    });
    crate::policy::EnvironmentSnapshot {
        inherit_host: false,
        bindings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty(_name: &str) -> Option<Vec<u8>> {
        None
    }

    #[test]
    fn tool_defaults_match_the_authoritative_table() {
        let baseline = baseline(ProfileName::Tool, Os::Linux, &empty);
        assert_eq!(
            baseline.limits.wall.as_ref().map(|value| value.value),
            Some(1_800_000)
        );
        assert_eq!(
            baseline.limits.pids.as_ref().map(|value| value.required),
            Some(false),
            "pids is preferred for tool, never required by default"
        );
        assert_eq!(baseline.limits.mem, None);
        assert_eq!(baseline.network_mode, NetworkMode::None);
        assert_eq!(
            baseline.protected_coverage,
            ProtectedCoverage::ExistingAndRoot
        );
    }

    #[test]
    fn none_inherits_the_host_and_claims_no_containment_authority() {
        let baseline = baseline(ProfileName::None, Os::Linux, &empty);
        assert!(baseline.environment.inherit_host);
        assert!(baseline.read_write.is_empty());
        assert!(baseline.read_only.is_empty());
        assert_eq!(baseline.network_mode, NetworkMode::Host);
        assert_eq!(
            baseline.limits.wall.as_ref().map(|value| value.value),
            Some(7_200_000)
        );
    }

    #[test]
    fn macos_claims_no_native_runtime_roots() {
        let baseline = baseline(ProfileName::Tool, Os::Macos, &empty);
        assert!(
            baseline.read_only.is_empty(),
            "no macOS mount plan is established by this milestone"
        );
    }

    #[test]
    fn the_contained_environment_carries_only_admitted_names() {
        let lookup = |name: &str| match name {
            "PATH" => Some(b"/usr/bin".to_vec()),
            "SECRET_TOKEN" => Some(b"leak".to_vec()),
            _ => None,
        };
        let baseline = baseline(ProfileName::Tool, Os::Linux, &lookup);
        let names: Vec<&str> = baseline
            .environment
            .bindings
            .iter()
            .map(|binding| binding.name.as_str())
            .collect();
        assert_eq!(names, vec!["PATH", "TMPDIR"]);
    }
}
