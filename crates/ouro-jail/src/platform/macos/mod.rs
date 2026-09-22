//! The macOS platform: policy inspection, and execution reported unsupported.
//!
//! Implements the macOS column of jail-v1 §3.2. This milestone ships no macOS
//! backend: containment, closed-set observation, process identity and tree
//! limits are all `unsupported`, and `run` refuses with exit 125 before exec,
//! including `--profile none` (§3.3: "Until it does, a policy requiring those
//! guarantees refuses, including `none`").
//!
//! Every method here returns a typed unsupported result. None of them is a
//! successful no-op, and none of them measures anything, so no capability row
//! claims a probe that did not run.

use crate::capability::{Capability, CapabilityScope, CapabilityStatus};
use crate::platform::{
    PlanRequest, Platform, PlatformIdentity, PreparedExecution, PreparedPlan, Sinks, kernel_release,
};
use crate::records::{ErrorCode, ErrorStage, JailError, Os, Remediation};

/// The reason code every macOS execution capability carries.
pub const REASON_UNSUPPORTED_PLATFORM: &str = "unsupported_platform";

/// The macOS platform implementation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MacosPlatform;

impl MacosPlatform {
    /// The refusal `prepare` and every execution path return.
    #[must_use]
    pub fn unsupported_error() -> JailError {
        JailError::new(
            ErrorCode::UnsupportedPlatform,
            ErrorStage::Probing,
            Remediation::Unsupported,
            "execution is not implemented for this platform".to_owned(),
        )
    }

    /// The capability scope a requirement is measured at.
    fn scope_for(requirement: &str) -> CapabilityScope {
        match requirement {
            "syscall_filter" => CapabilityScope::Process,
            _ => CapabilityScope::Tree,
        }
    }
}

impl Platform for MacosPlatform {
    fn identity(&self) -> PlatformIdentity {
        PlatformIdentity {
            os: Os::Macos,
            arch: std::env::consts::ARCH.to_owned(),
            kernel: kernel_release(),
        }
    }

    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        // No probe runs, so `measured_at` stays null: `unsupported` is a fact
        // about this implementation, not a measurement of this host.
        plan.requirements
            .iter()
            .map(|requirement| Capability {
                name: requirement.clone(),
                status: CapabilityStatus::Unsupported,
                scope: Self::scope_for(requirement),
                mechanism: None,
                reason_code: Some(REASON_UNSUPPORTED_PLATFORM.to_owned()),
                measured_at: None,
                evidence_ref: None,
            })
            .collect()
    }

    fn prepare(
        &self,
        _plan: PreparedPlan,
        _sinks: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        Err(Self::unsupported_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ProfileName, ResolveInputs, ScratchRoot};

    fn plan_for(profile: ProfileName) -> PlanRequest {
        let baseline = crate::profiles::baseline(profile, Os::Macos, &|_| None);
        let inputs = ResolveInputs {
            platform: Os::Macos,
            base_profile: profile,
            policy_name: profile.as_str().to_owned(),
            baseline,
            workspace: b"/work".to_vec(),
            scratch: ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        };
        let resolved = crate::policy::resolve(&inputs).expect("resolves");
        PlanRequest {
            snapshot: resolved.snapshot,
            profile,
            requirements: resolved.requirements,
        }
    }

    #[test]
    fn every_execution_capability_is_unsupported_and_unmeasured() {
        for profile in [ProfileName::Tool, ProfileName::None] {
            let plan = plan_for(profile);
            let capabilities = MacosPlatform.probe(&plan);
            assert!(
                !capabilities.is_empty(),
                "the plan derives at least one requirement"
            );
            for capability in capabilities {
                assert_eq!(
                    capability.status,
                    CapabilityStatus::Unsupported,
                    "{}",
                    capability.name
                );
                assert!(!capability.satisfies());
                assert_eq!(capability.measured_at, None, "no probe ran");
                assert_eq!(
                    capability.reason_code.as_deref(),
                    Some(REASON_UNSUPPORTED_PLATFORM)
                );
            }
        }
    }

    #[test]
    fn prepare_refuses_rather_than_returning_a_successful_no_op() {
        let plan = plan_for(ProfileName::None);
        let prepared = MacosPlatform.prepare(
            PreparedPlan {
                attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
                attempt_dir: std::path::PathBuf::from("/nonexistent"),
                request: plan,
                argv: vec![b"/bin/true".to_vec()],
                workspace: std::path::PathBuf::from("/work"),
                // J3-launch begin: the new hand-off field
                launch: None,
                // J3-launch end
            },
            Sinks { trace: None },
        );
        let error = match prepared {
            Ok(_) => panic!("macOS must not produce a prepared execution"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::UnsupportedPlatform);
        assert_eq!(error.exit_code(), 125);
    }
}
