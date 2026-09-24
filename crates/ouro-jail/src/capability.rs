//! Execution capabilities and the requirements a policy derives.
//!
//! Implements jail-v1 §3.1: a capability is a structured result, never a
//! boolean. `available` means a probe succeeded on this host with this
//! identity; `unsupported` means the implementation lacks it; `unavailable`
//! means prerequisites are missing. A `skipped` check cannot satisfy a
//! requirement, which [`satisfies`] enforces.

use serde::{Deserialize, Serialize};

use crate::policy::{LimitKey, PolicySnapshot, ProfileName, ProtectedCoverage};
use crate::records::ObserveMode;

/// The measured state of one capability (§3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// The relevant probe succeeded on this host with this identity.
    Available,
    /// The implementation exists but prerequisites are missing.
    Unavailable,
    /// This implementation does not have it at all.
    Unsupported,
    /// The probe itself failed.
    Error,
    /// The probe was not run. It can never satisfy a requirement.
    Skipped,
}

/// The scope a capability applies to (§3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityScope {
    /// One process.
    Process,
    /// The attempt tree.
    Tree,
    /// The whole host.
    Host,
}

/// One capability result (§3.1).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    /// The requirement identifier this result speaks about.
    pub name: String,
    /// What was measured.
    pub status: CapabilityStatus,
    /// The scope the result applies to.
    pub scope: CapabilityScope,
    /// The mechanism that was probed, when one exists.
    pub mechanism: Option<String>,
    /// A stable reason code for a non-available result.
    pub reason_code: Option<String>,
    /// When the probe ran, RFC 3339 UTC; null when it did not run.
    pub measured_at: Option<String>,
    /// A pointer to the evidence, when the probe produced any.
    pub evidence_ref: Option<String>,
}

impl Capability {
    /// A capability this platform does not implement at all.
    #[must_use]
    pub fn unsupported(name: impl Into<String>, scope: CapabilityScope, reason_code: &str) -> Self {
        Capability {
            name: name.into(),
            status: CapabilityStatus::Unsupported,
            scope,
            mechanism: None,
            reason_code: Some(reason_code.to_owned()),
            measured_at: None,
            evidence_ref: None,
        }
    }

    /// Whether this result can satisfy a requirement.
    ///
    /// Only `available` can. A `skipped` check never satisfies one (§3.1).
    #[must_use]
    pub fn satisfies(&self) -> bool {
        self.status == CapabilityStatus::Available
    }
}

/// Requirement identifier for tree-scoped termination.
pub const REQ_TREE_TERMINATION: &str = "tree_termination";
/// Requirement identifier for the closed-set observer.
pub const REQ_CLOSED_SET_OBSERVATION: &str = "closed_set_observation";
/// Requirement identifier for the filesystem boundary.
pub const REQ_FILESYSTEM_CONTAINMENT: &str = "filesystem_containment";
/// Requirement identifier for the syscall filter.
pub const REQ_SYSCALL_FILTER: &str = "syscall_filter";
/// Requirement identifier for a fully absent network.
pub const REQ_NETWORK_NONE: &str = "network_none";
/// Requirement identifier for the mediating proxy.
pub const REQ_NETWORK_PROXY: &str = "network_proxy";
// J5-D begin: the portable name (§3.1, I10; decided 2026-09-24)
/// Requirement identifier for a supervisor-owned execution boundary: a tree
/// the supervisor can place the target in, bound resources on, kill as a
/// whole and verify empty. `none` needs it for lifetime, and every explicit
/// tree ceiling needs it. How a platform provides it is its own plan (on
/// Linux, a delegated cgroup v2 leaf); the requirement names the semantic.
pub const REQ_EXECUTION_BOUNDARY: &str = "execution_boundary";
/// The Linux platform's spelling of [`REQ_EXECUTION_BOUNDARY`], which it
/// satisfies with a delegated cgroup. The same value: only the Rust name
/// differs, so the Linux mapping reads in its own vocabulary. Nothing
/// renders this name; the wire carries `execution_boundary`.
pub const REQ_EXECUTION_CGROUP: &str = REQ_EXECUTION_BOUNDARY;
// J5-D end
// J3-launch begin: credential staging requirement (§12)
/// Requirement identifier for staging launch credentials: anchored copies
/// into vendor state and read-only binds of the exact source objects.
pub const REQ_CREDENTIAL_STAGING: &str = "credential_staging";
// J3-launch end

/// Derives the capability requirements a snapshot implies (§6.4, §3.1).
///
/// Only requirements are derived here. Whether the host offers them is a
/// separate measurement, which `explain` explicitly reports as unmeasured.
#[must_use]
pub fn requirements(snapshot: &PolicySnapshot) -> Vec<String> {
    let mut out = vec![REQ_TREE_TERMINATION.to_owned()];
    if snapshot.observation.mode == ObserveMode::On {
        out.push(REQ_CLOSED_SET_OBSERVATION.to_owned());
    }
    if snapshot.profile.is_contained() {
        out.push(REQ_FILESYSTEM_CONTAINMENT.to_owned());
        out.push(REQ_SYSCALL_FILTER.to_owned());
    }
    match snapshot.network.mode.as_str() {
        "none" if snapshot.profile.is_contained() => out.push(REQ_NETWORK_NONE.to_owned()),
        "proxy" => out.push(REQ_NETWORK_PROXY.to_owned()),
        _ => {}
    }
    // J3-none begin: restrictions `none` cannot apply are requirements it refuses
    out.extend(none_restrictions(snapshot));
    // J3-none end
    if snapshot.filesystem.protected_coverage != ProtectedCoverage::None {
        out.push(format!(
            "protected_coverage:{}",
            snapshot.filesystem.protected_coverage.as_str()
        ));
    }
    // §4.9 of the north star: `none` still needs an execution boundary the
    // supervisor can kill (a cgroup on Linux), including with observation
    // off; that is its only lifetime boundary.
    let mut needs_cgroup = snapshot.profile == ProfileName::None;
    for key in LimitKey::ALL {
        let ceiling = match key {
            LimitKey::Wall => &snapshot.limits.wall,
            LimitKey::Pids => &snapshot.limits.pids,
            LimitKey::Mem => &snapshot.limits.mem,
            LimitKey::Cpu => &snapshot.limits.cpu,
        };
        if let Some(ceiling) = ceiling
            && ceiling.required
        {
            out.push(format!("limit:{}", key.as_str()));
            if key != LimitKey::Wall {
                needs_cgroup = true;
            }
        }
    }
    if needs_cgroup {
        out.push(REQ_EXECUTION_BOUNDARY.to_owned());
    }
    // J3-launch begin: a launch profile that declares credentials needs them
    // staged, and a platform that cannot stage them must refuse, not skip.
    if snapshot
        .launch
        .as_ref()
        .is_some_and(|launch| !launch.credentials.is_empty())
    {
        out.push(REQ_CREDENTIAL_STAGING.to_owned());
    }
    // J3-launch end
    out
}

// J3-none begin: what `none` cannot apply refuses instead of running unapplied
/// The reason code of a requirement the uncontained profile cannot satisfy on
/// any host, because it applies no filesystem, syscall or network
/// restriction (§3.1, §9.3).
pub const REASON_NOT_APPLIED_BY_NONE: &str = "uncontained_profile";

/// The requirements a `none` snapshot's restrictions derive.
///
/// `none` mounts, filters and isolates nothing, and a narrowing layer may
/// still ask for a restriction (§6.3: add a denied subtree, make a subtree
/// read-only, change the network to none). Each one becomes the requirement
/// a contained profile would satisfy, which `none` reports unsatisfiable, so
/// the run refuses instead of executing with the restriction dropped (I02).
/// Protected coverage already derives its own requirement above.
fn none_restrictions(snapshot: &PolicySnapshot) -> Vec<String> {
    let mut out = Vec::new();
    if snapshot.profile != ProfileName::None {
        return out;
    }
    if !snapshot.filesystem.deny_read.is_empty() || !snapshot.filesystem.read_only.is_empty() {
        out.push(REQ_FILESYSTEM_CONTAINMENT.to_owned());
    }
    if snapshot.network.mode.as_str() == "none" {
        out.push(REQ_NETWORK_NONE.to_owned());
    }
    out
}
// J3-none end

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::Os;

    fn snapshot_for(profile: ProfileName) -> PolicySnapshot {
        let baseline = crate::profiles::baseline(profile, Os::Linux, &|_| None);
        let inputs = crate::policy::ResolveInputs {
            platform: Os::Linux,
            base_profile: profile,
            policy_name: profile.as_str().to_owned(),
            baseline,
            workspace: b"/work".to_vec(),
            scratch: crate::policy::ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        };
        crate::policy::resolve(&inputs)
            .expect("the built-in baseline resolves")
            .snapshot
    }

    #[test]
    fn a_skipped_probe_never_satisfies_a_requirement() {
        let mut capability =
            Capability::unsupported(REQ_TREE_TERMINATION, CapabilityScope::Tree, "x");
        capability.status = CapabilityStatus::Skipped;
        assert!(!capability.satisfies());
        capability.status = CapabilityStatus::Available;
        assert!(capability.satisfies());
    }

    #[test]
    fn tool_requires_containment_observation_and_a_wall() {
        let requirements = requirements(&snapshot_for(ProfileName::Tool));
        for expected in [
            REQ_TREE_TERMINATION,
            REQ_CLOSED_SET_OBSERVATION,
            REQ_FILESYSTEM_CONTAINMENT,
            REQ_SYSCALL_FILTER,
            REQ_NETWORK_NONE,
            "protected_coverage:existing_and_root",
            "limit:wall",
        ] {
            assert!(
                requirements.iter().any(|item| item == expected),
                "missing {expected} in {requirements:?}"
            );
        }
        assert!(
            !requirements.iter().any(|item| item == "limit:pids"),
            "a preferred pids ceiling is never a requirement"
        );
    }

    // J3-none begin: narrowed `none` snapshots carry the restriction as a requirement
    #[test]
    fn a_restriction_on_none_is_a_requirement_not_a_silent_drop() {
        let bare = requirements(&snapshot_for(ProfileName::None));
        assert!(!bare.iter().any(|item| item == REQ_NETWORK_NONE));

        let mut denied = snapshot_for(ProfileName::None);
        denied.filesystem.deny_read.push(crate::policy::PathRef {
            root: crate::policy::RootToken::Workspace,
            path: crate::records::NativeString::Text("secret".to_owned()),
        });
        assert!(
            requirements(&denied)
                .iter()
                .any(|item| item == REQ_FILESYSTEM_CONTAINMENT)
        );

        let mut read_only = snapshot_for(ProfileName::None);
        read_only.filesystem.read_only.push(crate::policy::PathRef {
            root: crate::policy::RootToken::Workspace,
            path: crate::records::NativeString::Text("fixtures".to_owned()),
        });
        assert!(
            requirements(&read_only)
                .iter()
                .any(|item| item == REQ_FILESYSTEM_CONTAINMENT)
        );

        let mut isolated = snapshot_for(ProfileName::None);
        isolated.network.mode = "none".to_owned();
        assert!(
            requirements(&isolated)
                .iter()
                .any(|item| item == REQ_NETWORK_NONE)
        );
    }
    // J3-none end

    #[test]
    fn none_requires_a_cgroup_but_no_containment() {
        let requirements = requirements(&snapshot_for(ProfileName::None));
        // J5-D: the portable name of the tree boundary (§3.1, I10); how a
        // platform provides it (a cgroup on Linux) is the platform's plan.
        assert!(requirements.iter().any(|item| item == "execution_boundary"));
        assert!(
            !requirements
                .iter()
                .any(|item| item == REQ_FILESYSTEM_CONTAINMENT)
        );
        assert!(
            requirements
                .iter()
                .any(|item| item == REQ_CLOSED_SET_OBSERVATION)
        );
    }
}
