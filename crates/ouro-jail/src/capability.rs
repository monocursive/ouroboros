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
/// Requirement identifier for a supervisor-owned execution cgroup.
pub const REQ_EXECUTION_CGROUP: &str = "execution_cgroup";

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
    if snapshot.filesystem.protected_coverage != ProtectedCoverage::None {
        out.push(format!(
            "protected_coverage:{}",
            snapshot.filesystem.protected_coverage.as_str()
        ));
    }
    // §4.9 of the north star: `none` still needs a cgroup the supervisor can
    // kill, including with observation off; that is its only lifetime boundary.
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
        out.push(REQ_EXECUTION_CGROUP.to_owned());
    }
    out
}

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

    #[test]
    fn none_requires_a_cgroup_but_no_containment() {
        let requirements = requirements(&snapshot_for(ProfileName::None));
        assert!(requirements.iter().any(|item| item == REQ_EXECUTION_CGROUP));
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
