//! From probe results to the plan's capabilities (§4, §14.1).

use crate::capability::{Capability, CapabilityScope, CapabilityStatus, Requirement};
use crate::platform::PlanRequest;
use crate::policy::LimitKey;

use super::probe::{ProbeResult, ProbeStatus};

// ---------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------

pub(super) fn status_of(result: &ProbeResult) -> CapabilityStatus {
    match result.status {
        ProbeStatus::Available => CapabilityStatus::Available,
        ProbeStatus::Unavailable => CapabilityStatus::Unavailable,
        ProbeStatus::Unsupported => CapabilityStatus::Unsupported,
        ProbeStatus::Error => CapabilityStatus::Error,
        ProbeStatus::Skipped => CapabilityStatus::Skipped,
    }
}

/// Which probes establish a requirement, the mechanism it names and the
/// scope it is measured at.
fn inputs_for(
    requirement: Requirement,
) -> (&'static [&'static str], &'static str, CapabilityScope) {
    match requirement {
        Requirement::TreeTermination => (
            &["bwrap_present", "pid_namespace"],
            "pid-namespace",
            CapabilityScope::Tree,
        ),
        Requirement::ClosedSetObservation => (
            &["ptrace_seize_descendant", "observer_closed_set"],
            "ptrace",
            CapabilityScope::Tree,
        ),
        // Protected coverage rests on the same binds the filesystem boundary
        // does.
        Requirement::FilesystemContainment | Requirement::ProtectedCoverage(_) => (
            &["bwrap_present", "user_namespace", "mount_readonly_bind"],
            "bubblewrap-binds",
            CapabilityScope::Tree,
        ),
        Requirement::SyscallFilter => (
            &["seccomp_filter_load"],
            "seccomp-bpf",
            CapabilityScope::Process,
        ),
        Requirement::NetworkNone => (
            &["network_namespace"],
            "network-namespace",
            CapabilityScope::Tree,
        ),
        // The agent network rests on the empty network
        // namespace and the unix-peer mediation's kernel mechanism; the proxy
        // and the bridge are this implementation's own, and preparation
        // refuses naming either one it cannot establish (§10).
        Requirement::NetworkProxy => (
            &[
                "bwrap_present",
                "network_namespace",
                "seccomp_user_notification",
                "unix_socket_diagnostics",
            ],
            "network-namespace+outside-http-proxy+loopback-bridge+unix-peer-mediation",
            CapabilityScope::Tree,
        ),
        // The execution boundary is a delegated cgroup v2 leaf here.
        Requirement::ExecutionBoundary => (
            &["cgroup_delegated_leaf"],
            "cgroup-v2-delegated",
            CapabilityScope::Tree,
        ),
        // Credential staging is anchored copies into vendor
        // state plus read-only descriptor binds, which rest on the backend and
        // on its read-only bind holding.
        Requirement::CredentialStaging => (
            &["bwrap_present", "mount_readonly_bind"],
            "anchored-copy+bubblewrap-bind-fd",
            CapabilityScope::Tree,
        ),
        // The wall is this supervisor's own CLOCK_BOOTTIME deadline; no host
        // mechanism has to provide it (see `capability_for`).
        Requirement::Limit(LimitKey::Wall) => (&[], "boottime-deadline", CapabilityScope::Tree),
        Requirement::Limit(LimitKey::Pids) => (
            &["cgroup_pids"],
            "cgroup-v2-delegated",
            CapabilityScope::Tree,
        ),
        Requirement::Limit(LimitKey::Mem) => (
            &["cgroup_memory"],
            "cgroup-v2-delegated",
            CapabilityScope::Tree,
        ),
        Requirement::Limit(LimitKey::Swap) => (
            &["cgroup_swap"],
            "cgroup-v2-delegated",
            CapabilityScope::Tree,
        ),
        Requirement::Limit(LimitKey::Cpu) => (
            &["cgroup_cpu"],
            "cgroup-v2-delegated",
            CapabilityScope::Tree,
        ),
        Requirement::Limit(LimitKey::Storage | LimitKey::Inodes) => (
            &["storage_ceiling"],
            "bounded-tmpfs-or-user-quota",
            CapabilityScope::Tree,
        ),
    }
}

/// The probes one requirement's capability is derived from. A run measures
/// only these; `doctor` measures every probe.
pub(super) fn probes_for(requirement: Requirement) -> &'static [&'static str] {
    inputs_for(requirement).0
}

pub(super) fn capability_for(
    requirement: Requirement,
    results: &[ProbeResult],
    measured_at: &str,
) -> Capability {
    let (probes, mechanism, scope) = inputs_for(requirement);
    if requirement == Requirement::Limit(LimitKey::Wall) {
        // The wall is this supervisor's own CLOCK_BOOTTIME deadline; no host
        // mechanism has to provide it.
        return Capability {
            name: requirement.to_string(),
            status: CapabilityStatus::Available,
            scope,
            mechanism: Some(mechanism.to_owned()),
            reason_code: Some("ok".to_owned()),
            measured_at: Some(measured_at.to_owned()),
            evidence_ref: Some("supervisor".to_owned()),
        };
    }
    capability_from(requirement, probes, mechanism, scope, results, measured_at)
}

pub(super) fn capability_from(
    requirement: Requirement,
    probes: &[&str],
    mechanism: &str,
    scope: CapabilityScope,
    results: &[ProbeResult],
    measured_at: &str,
) -> Capability {
    let mut status = CapabilityStatus::Available;
    let mut reason = "ok".to_owned();
    for name in probes {
        let Some(result) = results.iter().find(|item| item.name == *name) else {
            status = CapabilityStatus::Skipped;
            reason = "probe_not_run".to_owned();
            break;
        };
        if result.status != ProbeStatus::Available {
            status = status_of(result);
            reason = result.reason_code.to_owned();
            break;
        }
    }
    Capability {
        name: requirement.to_string(),
        status,
        scope,
        mechanism: Some(mechanism.to_owned()),
        reason_code: Some(reason),
        measured_at: Some(measured_at.to_owned()),
        evidence_ref: Some(probes.join(",")),
    }
}

// J5-D: the derivation apart from the probing, so the requirement→probe
// mapping is testable with stated results (review F12).
/// The plan's capabilities from the probe results: one row per requirement
/// (through [`capability_for`] and `none`'s own mapping), then the probe
/// rows.
pub(super) fn derive(
    plan: &PlanRequest,
    results: &[ProbeResult],
    measured_at: &str,
) -> Vec<Capability> {
    // `none` terminates its tree through the delegated leaf (§9.3)
    // Shadows the fn for this call only; the closure falls back to it.
    let capability_for = |requirement: Requirement, results: &[ProbeResult], measured_at: &str| {
        super::uncontained::capability_for(plan.snapshot.profile, requirement, results, measured_at)
            .unwrap_or_else(|| capability_for(requirement, results, measured_at))
    };
    let mut out: Vec<Capability> = plan
        .requirements
        .iter()
        .map(|requirement| capability_for(*requirement, results, measured_at))
        .collect();
    // The probe rows themselves, so `doctor --json` reports what was
    // measured and not only what the plan happened to ask for (§14.1).
    for result in results {
        out.push(Capability {
            name: result.name.to_owned(),
            status: status_of(result),
            scope: CapabilityScope::Host,
            mechanism: Some(result.mechanism.to_owned()),
            reason_code: Some(result.reason_code.to_owned()),
            measured_at: Some(measured_at.to_owned()),
            evidence_ref: Some(result.evidence.clone()),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::platform::tests::plan_request;
    use super::*;

    /// Review F12: through the real requirement→probe mapping, a build for
    /// an architecture the tables do not cover leaves the filter, observer
    /// and proxy requirements unsupported (so `run` refuses before
    /// preparation), and nothing else: `none` with observation off still
    /// derives every requirement it needs.
    #[test]
    fn unsupported_architectures_the_real_mapping_refuses_exactly_the_table_bound_requirements() {
        use super::super::probe::{self, ProbeResult, ProbeStatus};
        use crate::policy::ProfileName;
        let results: Vec<ProbeResult> = probe::PROBE_NAMES
            .iter()
            .map(|name| {
                probe::architecture_refusal(name, "riscv64").unwrap_or_else(|| ProbeResult {
                    name,
                    status: ProbeStatus::Available,
                    mechanism: "test",
                    reason_code: "ok",
                    evidence: String::new(),
                })
            })
            .collect();
        let refused = [
            Requirement::SyscallFilter,
            Requirement::ClosedSetObservation,
            Requirement::NetworkProxy,
        ];
        for (profile, observe_off, expected) in [
            (
                ProfileName::Tool,
                false,
                &[
                    Requirement::SyscallFilter,
                    Requirement::ClosedSetObservation,
                ][..],
            ),
            (ProfileName::Tool, true, &[Requirement::SyscallFilter][..]),
            (
                ProfileName::Build,
                false,
                &[
                    Requirement::SyscallFilter,
                    Requirement::ClosedSetObservation,
                ][..],
            ),
            (
                ProfileName::Agent,
                false,
                &[
                    Requirement::SyscallFilter,
                    Requirement::ClosedSetObservation,
                    Requirement::NetworkProxy,
                ][..],
            ),
            (
                ProfileName::None,
                false,
                &[Requirement::ClosedSetObservation][..],
            ),
            (ProfileName::None, true, &[][..]),
        ] {
            let plan = plan_request(profile, observe_off);
            let capabilities = super::derive(&plan, &results, "2026-09-24T00:00:00Z");
            let mut unsatisfied = Vec::new();
            for &requirement in &plan.requirements {
                let row = capabilities
                    .iter()
                    .find(|row| requirement.answered_by(row))
                    .unwrap_or_else(|| panic!("{profile:?}: no row for {requirement}"));
                if row.satisfies() {
                    continue;
                }
                assert_eq!(
                    row.status,
                    CapabilityStatus::Unsupported,
                    "{profile:?} {requirement}"
                );
                assert_eq!(
                    row.reason_code.as_deref(),
                    Some("unsupported_architecture"),
                    "{profile:?} {requirement}"
                );
                assert!(refused.contains(&requirement), "{requirement}");
                unsatisfied.push(requirement);
            }
            let mut expected = expected.to_vec();
            expected.sort_unstable();
            unsatisfied.sort_unstable();
            assert_eq!(
                unsatisfied, expected,
                "{profile:?} observe_off={observe_off}"
            );
        }
    }

    #[test]
    fn a_run_probes_only_what_its_requirements_name() {
        assert!(super::probes_for(Requirement::Limit(LimitKey::Wall)).is_empty());
        // J3-agent: the agent network is measured, never granted for free.
        assert_eq!(
            super::probes_for(Requirement::NetworkProxy),
            [
                "bwrap_present",
                "network_namespace",
                "seccomp_user_notification",
                "unix_socket_diagnostics"
            ]
        );
        assert_eq!(
            super::probes_for(Requirement::Limit(LimitKey::Pids)),
            ["cgroup_pids"]
        );
        assert_eq!(
            super::probes_for(Requirement::Limit(LimitKey::Mem)),
            ["cgroup_memory"]
        );
        assert_eq!(
            super::probes_for(Requirement::Limit(LimitKey::Storage)),
            ["storage_ceiling"]
        );
        assert_eq!(
            super::probes_for(Requirement::Limit(LimitKey::Inodes)),
            ["storage_ceiling"]
        );
        assert_eq!(
            super::probes_for(Requirement::Limit(LimitKey::Cpu)),
            ["cgroup_cpu"]
        );
        assert_eq!(
            super::probes_for(Requirement::ProtectedCoverage(
                crate::policy::ProtectedCoverage::ExistingAndRoot
            )),
            super::probes_for(Requirement::FilesystemContainment)
        );
        assert!(
            super::probes_for(Requirement::ClosedSetObservation).contains(&"observer_closed_set")
        );
    }

    #[test]
    fn a_missing_probe_makes_the_requirement_skipped_not_available() {
        let capability = capability_for(Requirement::SyscallFilter, &[], "2026-09-22T00:00:00Z");
        assert_eq!(capability.status, CapabilityStatus::Skipped);
        assert_eq!(capability.reason_code.as_deref(), Some("probe_not_run"));
        assert!(!capability.satisfies());
    }

    #[test]
    fn the_wall_is_the_supervisors_own_mechanism() {
        let capability = capability_for(
            Requirement::Limit(LimitKey::Wall),
            &[],
            "2026-09-22T00:00:00Z",
        );
        assert!(capability.satisfies());
        assert_eq!(capability.mechanism.as_deref(), Some("boottime-deadline"));
    }

    #[test]
    fn storage_ceilings_rest_on_the_storage_ceiling_probe() {
        // L6: the rows no longer claim the filesystem-containment probes.
        let unmeasured = capability_for(
            Requirement::Limit(LimitKey::Storage),
            &[],
            "2026-09-22T00:00:00Z",
        );
        assert_eq!(unmeasured.status, CapabilityStatus::Skipped);
        assert_eq!(
            unmeasured.mechanism.as_deref(),
            Some("bounded-tmpfs-or-user-quota")
        );
        let probe = |status, reason: &'static str| ProbeResult {
            name: "storage_ceiling",
            status,
            mechanism: "bounded-tmpfs-or-user-quota",
            reason_code: reason,
            evidence: String::new(),
        };
        let refused = capability_for(
            Requirement::Limit(LimitKey::Storage),
            &[probe(ProbeStatus::Unavailable, "no_user_hard_quota")],
            "2026-09-22T00:00:00Z",
        );
        assert_eq!(refused.status, CapabilityStatus::Unavailable);
        assert_eq!(refused.reason_code.as_deref(), Some("no_user_hard_quota"));
        let unbounded = capability_for(
            Requirement::Limit(LimitKey::Inodes),
            &[probe(ProbeStatus::Unavailable, "tmpfs_unbounded")],
            "2026-09-22T00:00:00Z",
        );
        assert_eq!(unbounded.status, CapabilityStatus::Unavailable);
        assert!(
            capability_for(
                Requirement::Limit(LimitKey::Inodes),
                &[probe(ProbeStatus::Available, "ok")],
                "2026-09-22T00:00:00Z"
            )
            .satisfies()
        );
    }

    #[test]
    fn a_proxy_requirement_rests_on_measured_probes_and_never_on_a_skip() {
        // J3-agent: no longer unsupported; derived from what was measured.
        let unmeasured = capability_for(Requirement::NetworkProxy, &[], "2026-09-22T00:00:00Z");
        assert_eq!(unmeasured.status, CapabilityStatus::Skipped);
        let ok = |name: &'static str| ProbeResult {
            name,
            status: ProbeStatus::Available,
            mechanism: "m",
            reason_code: "ok",
            evidence: String::new(),
        };
        let all = [
            ok("bwrap_present"),
            ok("network_namespace"),
            ok("seccomp_user_notification"),
            ok("unix_socket_diagnostics"),
        ];
        let measured = capability_for(Requirement::NetworkProxy, &all, "2026-09-22T00:00:00Z");
        assert_eq!(measured.status, CapabilityStatus::Available);
        let mut no_diag = all.clone();
        no_diag[3].status = ProbeStatus::Unavailable;
        no_diag[3].reason_code = "unix_socket_diagnostics_unavailable";
        let no_diag = capability_for(Requirement::NetworkProxy, &no_diag, "2026-09-22T00:00:00Z");
        assert_eq!(no_diag.status, CapabilityStatus::Unavailable);
        assert_eq!(
            no_diag.reason_code.as_deref(),
            Some("unix_socket_diagnostics_unavailable")
        );
        let mut refused = all.clone();
        refused[2].status = ProbeStatus::Unavailable;
        refused[2].reason_code = "listener_refused";
        let refused = capability_for(Requirement::NetworkProxy, &refused, "2026-09-22T00:00:00Z");
        assert_eq!(refused.status, CapabilityStatus::Unavailable);
        assert_eq!(refused.reason_code.as_deref(), Some("listener_refused"));
        assert_eq!(
            probes_for(Requirement::NetworkProxy),
            &[
                "bwrap_present",
                "network_namespace",
                "seccomp_user_notification",
                "unix_socket_diagnostics"
            ]
        );
    }
}
