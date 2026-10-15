//! Changes to a resolved policy after [`policy::resolve`](crate::policy::resolve).
//!
//! The snapshot is immutable once its digest names it (§6.2), but three
//! inputs complete it after the layers resolve: the launch profile's field
//! group (§12), the operator's command rules (jail-v2 §7.2) and `learn`'s
//! read capture. Each goes through [`Resolved::amend`], which applies the
//! change, records why in the provenance and recomputes everything derived
//! from the snapshot, so the digest a receipt names is always the digest of
//! the snapshot that ran, and no change reaches it unexplained.

use crate::capability;
use crate::policy::{PolicySnapshot, ProvenanceEntry, Resolved};
use crate::records::{ErrorCode, ErrorStage, JailError, Remediation};

impl Resolved {
    /// Applies `change` to the snapshot, records `why` in the provenance
    /// (never in the digest), and recomputes the snapshot's digest and its
    /// capability requirements.
    ///
    /// # Errors
    /// [`ErrorCode::InternalError`] when `why` is empty (an amendment that
    /// cannot say where it came from is a defect, never an input), the
    /// change's own refusal, or a snapshot that has no digest. The policy is
    /// then only partly changed and must be dropped, which every caller does
    /// by returning the error.
    pub(crate) fn amend(
        &mut self,
        why: Vec<ProvenanceEntry>,
        change: impl FnOnce(&mut PolicySnapshot) -> Result<(), JailError>,
    ) -> Result<(), JailError> {
        if why.is_empty() {
            return Err(JailError::new(
                ErrorCode::InternalError,
                ErrorStage::Resolving,
                Remediation::InspectState,
                "a change to the resolved policy records no reason".to_owned(),
            ));
        }
        change(&mut self.snapshot)?;
        self.provenance.extend(why);
        self.digest = self.snapshot.digest()?;
        self.requirements = capability::requirements(&self.snapshot);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::policy::{self, ProfileName, ProvenanceEntry, ResolveInputs, ScratchRoot};
    use crate::records::{ErrorCode, ErrorStage, JailError, ObserveMode, Os, Remediation};

    fn resolved() -> crate::policy::Resolved {
        policy::resolve(&ResolveInputs {
            platform: Os::Linux,
            base_profile: ProfileName::Tool,
            policy_name: "tool".to_owned(),
            baseline: crate::profiles::baseline(ProfileName::Tool, Os::Linux, &|_| None),
            workspace: b"/work".to_vec(),
            scratch: ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        })
        .expect("resolves")
    }

    fn why(key: &str) -> Vec<ProvenanceEntry> {
        vec![ProvenanceEntry {
            origin: "cli".to_owned(),
            key: key.to_owned(),
            detail: None,
        }]
    }

    /// An amendment changes the digest to the amended snapshot's, rederives
    /// the requirements from it and says why; the reason itself is no digest
    /// input.
    #[test]
    fn an_amendment_redigests_rederives_and_records_why() {
        let mut amended = resolved();
        let before = amended.clone();
        amended
            .amend(why("observation.mode"), |snapshot| {
                snapshot.observation.mode = ObserveMode::Off;
                Ok(())
            })
            .unwrap();
        assert_eq!(amended.digest, amended.snapshot.digest().unwrap());
        assert_ne!(amended.digest, before.digest);
        assert_eq!(
            amended.requirements,
            crate::capability::requirements(&amended.snapshot)
        );
        assert_ne!(
            amended.requirements, before.requirements,
            "observation off drops the closed-set requirement"
        );
        assert_eq!(amended.provenance.last(), why("observation.mode").last());

        let mut other = resolved();
        let mut reason = why("observation.mode");
        reason[0].origin = "operator-config:config.toml".to_owned();
        other
            .amend(reason, |snapshot| {
                snapshot.observation.mode = ObserveMode::Off;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            other.digest, amended.digest,
            "provenance is no digest input"
        );
    }

    /// A refused change is returned as it is.
    #[test]
    fn a_refused_change_is_the_amendments_error() {
        let refusal = JailError::new(
            ErrorCode::InvalidConfig,
            ErrorStage::Resolving,
            Remediation::Configuration,
            "no".to_owned(),
        );
        let error = resolved()
            .amend(why("launch"), |_| Err(refusal.clone()))
            .unwrap_err();
        assert_eq!(error, refusal);
    }

    /// An amendment that says nothing about where it came from changes
    /// nothing and refuses.
    #[test]
    fn an_amendment_without_a_reason_refuses_and_changes_nothing() {
        let mut amended = resolved();
        let before = amended.clone();
        let error = amended
            .amend(Vec::new(), |snapshot| {
                snapshot.observation.mode = ObserveMode::Off;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InternalError);
        assert_eq!(amended, before);
    }
}
