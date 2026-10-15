//! Execution capabilities and the requirements a policy derives.
//!
//! Implements jail-v1 §3.1: a capability is a structured result, never a
//! boolean. `available` means a probe succeeded on this host with this
//! identity; `unsupported` means the implementation lacks it; `unavailable`
//! means prerequisites are missing. A `skipped` check cannot satisfy a
//! requirement, which [`satisfies`] enforces.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::network::NetworkMode;
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

impl CapabilityStatus {
    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CapabilityStatus::Available => "available",
            CapabilityStatus::Unavailable => "unavailable",
            CapabilityStatus::Unsupported => "unsupported",
            CapabilityStatus::Error => "error",
            CapabilityStatus::Skipped => "skipped",
        }
    }
}

impl CapabilityScope {
    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CapabilityScope::Process => "process",
            CapabilityScope::Tree => "tree",
            CapabilityScope::Host => "host",
        }
    }
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

/// A capability requirement a policy derives (§3.1, §6.4).
///
/// Its wire spelling ([`fmt::Display`]) is what `explain` and `doctor`
/// list, what a receipt's `policy.requirements` carries and what the
/// capability that answers it is named: one spelling, so a requirement is
/// never re-parsed from its own text.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Requirement {
    /// `tree_termination`: the attempt's tree can be ended as a whole.
    TreeTermination,
    /// `closed_set_observation`: the closed-set observer.
    ClosedSetObservation,
    /// `filesystem_containment`: the filesystem boundary.
    FilesystemContainment,
    /// `syscall_filter`: the syscall filter.
    SyscallFilter,
    /// `network_none`: a fully absent network.
    NetworkNone,
    /// `network_proxy`: the mediating proxy.
    NetworkProxy,
    // The portable name (§3.1, I10; decided 2026-09-24)
    /// `execution_boundary`: a supervisor-owned execution boundary, a tree
    /// the supervisor can place the target in, bound resources on, kill as
    /// a whole and verify empty. `none` needs it for lifetime, and every
    /// explicit tree ceiling needs it. How a platform provides it is its own
    /// plan (on Linux, a delegated cgroup v2 leaf); the requirement names
    /// the semantic.
    ExecutionBoundary,
    /// `credential_staging`: anchored copies of launch credentials into
    /// vendor state and read-only binds of the exact source objects (§12).
    CredentialStaging,
    /// `protected_coverage:<coverage>`: protected segments covered as the
    /// policy asks.
    ProtectedCoverage(ProtectedCoverage),
    /// `limit:<key>`: an explicit, required ceiling.
    Limit(LimitKey),
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Requirement::TreeTermination => f.write_str("tree_termination"),
            Requirement::ClosedSetObservation => f.write_str("closed_set_observation"),
            Requirement::FilesystemContainment => f.write_str("filesystem_containment"),
            Requirement::SyscallFilter => f.write_str("syscall_filter"),
            Requirement::NetworkNone => f.write_str("network_none"),
            Requirement::NetworkProxy => f.write_str("network_proxy"),
            Requirement::ExecutionBoundary => f.write_str("execution_boundary"),
            Requirement::CredentialStaging => f.write_str("credential_staging"),
            Requirement::ProtectedCoverage(coverage) => {
                write!(f, "protected_coverage:{}", coverage.as_str())
            }
            Requirement::Limit(key) => write!(f, "limit:{}", key.as_str()),
        }
    }
}

impl Serialize for Requirement {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl Requirement {
    /// Whether `capability` answers this requirement: it carries its name.
    #[must_use]
    pub fn answered_by(self, capability: &Capability) -> bool {
        capability.name == self.to_string()
    }
}

/// Derives the capability requirements a snapshot implies (§6.4, §3.1).
///
/// Only requirements are derived here. Whether the host offers them is a
/// separate measurement, which `explain` explicitly reports as unmeasured.
#[must_use]
pub fn requirements(snapshot: &PolicySnapshot) -> Vec<Requirement> {
    let mut out = vec![Requirement::TreeTermination];
    if snapshot.observation.mode == ObserveMode::On {
        out.push(Requirement::ClosedSetObservation);
    }
    if snapshot.profile.is_contained() {
        out.push(Requirement::FilesystemContainment);
        out.push(Requirement::SyscallFilter);
    }
    match snapshot.network.mode {
        NetworkMode::None if snapshot.profile.is_contained() => {
            out.push(Requirement::NetworkNone);
        }
        NetworkMode::Proxy => out.push(Requirement::NetworkProxy),
        NetworkMode::None | NetworkMode::Host => {}
    }
    // Restrictions `none` cannot apply are requirements it refuses
    out.extend(none_restrictions(snapshot));
    if snapshot.filesystem.protected_coverage != ProtectedCoverage::None {
        out.push(Requirement::ProtectedCoverage(
            snapshot.filesystem.protected_coverage,
        ));
    }
    // §4.9 of the north star: `none` still needs an execution boundary the
    // supervisor can kill (a cgroup on Linux), including with observation
    // off; that is its only lifetime boundary.
    let mut needs_cgroup = snapshot.profile == ProfileName::None;
    for key in LimitKey::ALL {
        if let Some(ceiling) = snapshot.limits.get(key)
            && ceiling.required
        {
            out.push(Requirement::Limit(key));
            if matches!(
                key,
                LimitKey::Pids | LimitKey::Mem | LimitKey::Swap | LimitKey::Cpu
            ) {
                needs_cgroup = true;
            }
        }
    }
    if needs_cgroup {
        out.push(Requirement::ExecutionBoundary);
    }
    // A launch profile that declares credentials needs them
    // staged, and a platform that cannot stage them must refuse, not skip.
    if snapshot
        .launch
        .as_ref()
        .is_some_and(|launch| !launch.credentials.is_empty())
    {
        out.push(Requirement::CredentialStaging);
    }
    out
}

// What `none` cannot apply refuses instead of running unapplied
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
fn none_restrictions(snapshot: &PolicySnapshot) -> Vec<Requirement> {
    let mut out = Vec::new();
    if snapshot.profile != ProfileName::None {
        return out;
    }
    if !snapshot.filesystem.deny_read.is_empty() || !snapshot.filesystem.read_only.is_empty() {
        out.push(Requirement::FilesystemContainment);
    }
    if snapshot.network.mode == NetworkMode::None {
        out.push(Requirement::NetworkNone);
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
        let mut capability = Capability::unsupported(
            Requirement::TreeTermination.to_string(),
            CapabilityScope::Tree,
            "x",
        );
        capability.status = CapabilityStatus::Skipped;
        assert!(!capability.satisfies());
        capability.status = CapabilityStatus::Available;
        assert!(capability.satisfies());
    }

    /// Every requirement's wire spelling, as `explain`, `doctor` and the
    /// receipt carry it.
    #[test]
    fn each_requirement_has_its_wire_spelling() {
        for (requirement, spelled) in [
            (Requirement::TreeTermination, "tree_termination"),
            (Requirement::ClosedSetObservation, "closed_set_observation"),
            (Requirement::FilesystemContainment, "filesystem_containment"),
            (Requirement::SyscallFilter, "syscall_filter"),
            (Requirement::NetworkNone, "network_none"),
            (Requirement::NetworkProxy, "network_proxy"),
            (Requirement::ExecutionBoundary, "execution_boundary"),
            (Requirement::CredentialStaging, "credential_staging"),
            (
                Requirement::ProtectedCoverage(ProtectedCoverage::AllDescendants),
                "protected_coverage:all_descendants",
            ),
            (Requirement::Limit(LimitKey::Inodes), "limit:inodes"),
        ] {
            assert_eq!(requirement.to_string(), spelled);
            assert_eq!(
                serde_json::to_value(requirement).unwrap(),
                serde_json::Value::from(spelled)
            );
        }
    }

    #[test]
    fn tool_requires_containment_observation_and_a_wall() {
        let requirements = requirements(&snapshot_for(ProfileName::Tool));
        for expected in [
            Requirement::TreeTermination,
            Requirement::ClosedSetObservation,
            Requirement::FilesystemContainment,
            Requirement::SyscallFilter,
            Requirement::NetworkNone,
            Requirement::ProtectedCoverage(ProtectedCoverage::ExistingAndRoot),
            Requirement::Limit(LimitKey::Wall),
        ] {
            assert!(
                requirements.contains(&expected),
                "missing {expected} in {requirements:?}"
            );
        }
        assert!(
            !requirements.contains(&Requirement::Limit(LimitKey::Pids)),
            "a preferred pids ceiling is never a requirement"
        );
    }

    // Narrowed `none` snapshots carry the restriction as a requirement
    #[test]
    fn a_restriction_on_none_is_a_requirement_not_a_silent_drop() {
        let bare = requirements(&snapshot_for(ProfileName::None));
        assert!(!bare.contains(&Requirement::NetworkNone));

        let mut denied = snapshot_for(ProfileName::None);
        denied.filesystem.deny_read.push(crate::policy::PathRef {
            root: crate::policy::RootToken::Workspace,
            path: crate::records::NativeString::Text("secret".to_owned()),
        });
        assert!(requirements(&denied).contains(&Requirement::FilesystemContainment));

        let mut read_only = snapshot_for(ProfileName::None);
        read_only.filesystem.read_only.push(crate::policy::PathRef {
            root: crate::policy::RootToken::Workspace,
            path: crate::records::NativeString::Text("fixtures".to_owned()),
        });
        assert!(requirements(&read_only).contains(&Requirement::FilesystemContainment));

        let mut isolated = snapshot_for(ProfileName::None);
        isolated.network.mode = NetworkMode::None;
        assert!(requirements(&isolated).contains(&Requirement::NetworkNone));
    }

    #[test]
    fn none_requires_a_cgroup_but_no_containment() {
        let requirements = requirements(&snapshot_for(ProfileName::None));
        // J5-D: the portable name of the tree boundary (§3.1, I10); how a
        // platform provides it (a cgroup on Linux) is the platform's plan.
        assert!(requirements.contains(&Requirement::ExecutionBoundary));
        assert!(!requirements.contains(&Requirement::FilesystemContainment));
        assert!(requirements.contains(&Requirement::ClosedSetObservation));
    }

    /// Every tree-enforced ceiling — pids, mem, swap and cpu — needs the
    /// execution boundary, not just pids (audit survivor, capability.rs).
    #[test]
    fn every_tree_enforced_limit_requires_the_execution_boundary() {
        for key in [LimitKey::Pids, LimitKey::Mem, LimitKey::Swap, LimitKey::Cpu] {
            let mut snapshot = snapshot_for(ProfileName::None);
            let ceiling = crate::policy::LimitCeiling {
                value: "1".to_owned(),
                required: true,
            };
            *snapshot.limits.get_mut(key) = Some(ceiling);
            let requirements = requirements(&snapshot);
            assert!(
                requirements.contains(&Requirement::Limit(key)),
                "{key:?} ceiling is a requirement: {requirements:?}"
            );
            assert!(
                requirements.contains(&Requirement::ExecutionBoundary),
                "{key:?} requires the execution boundary: {requirements:?}"
            );
        }
    }
}
