//! The portable observer contract: the closed set, coverage and gaps.
//!
//! Implements jail-v1 §11.2 (the closed set `linux-closed-v1`) and §11.4 (loss
//! and coverage) as portable types. No platform code lives here; a backend
//! produces a [`CoverageSummary`] and this module turns it into the receipt's
//! `observer` and `coverage` groups.
//!
//! The class-to-source assignment of §11.4 is fixed here, so a proxy fact can
//! never populate a syscall class and an unsupported class can never carry a
//! count.

use std::collections::BTreeMap;

use crate::records::{
    CLOSED_SET_LINUX_V1, Coverage, CoverageEntry, Gap, ObserverRecord, SourceHealth, SourceStatus,
};

/// One operation in the closed set (§11.2).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ClosedOperation {
    /// A confirmed exec transition or a failed exec return.
    ProcExec,
    /// Final thread-group termination after a witnessed exec.
    ProcExit,
    /// A directory entry was created.
    FsCreate,
    /// A file was opened for possible mutation.
    FsWrite,
    /// A rename call returned.
    FsRename,
    /// A removal call returned.
    FsUnlink,
    /// A covered call returned EACCES or EPERM.
    FsDeny,
    /// A connect call returned.
    NetConnect,
}

impl ClosedOperation {
    /// Every operation, in a stable order.
    pub const ALL: [ClosedOperation; 8] = [
        ClosedOperation::ProcExec,
        ClosedOperation::ProcExit,
        ClosedOperation::FsCreate,
        ClosedOperation::FsWrite,
        ClosedOperation::FsRename,
        ClosedOperation::FsUnlink,
        ClosedOperation::FsDeny,
        ClosedOperation::NetConnect,
    ];

    /// The operation name used in the event envelope.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ClosedOperation::ProcExec => "proc.exec",
            ClosedOperation::ProcExit => "proc.exit",
            ClosedOperation::FsCreate => "fs.create",
            ClosedOperation::FsWrite => "fs.write",
            ClosedOperation::FsRename => "fs.rename",
            ClosedOperation::FsUnlink => "fs.unlink",
            ClosedOperation::FsDeny => "fs.deny",
            ClosedOperation::NetConnect => "net.connect",
        }
    }

    /// The coverage class this operation's results are counted under (§11.4).
    ///
    /// A denied `connect` counts once, under `fs.deny`, never under `net`.
    #[must_use]
    pub fn coverage_class(self) -> CoverageClass {
        match self {
            ClosedOperation::ProcExec | ClosedOperation::ProcExit => CoverageClass::Exec,
            ClosedOperation::FsCreate
            | ClosedOperation::FsWrite
            | ClosedOperation::FsRename
            | ClosedOperation::FsUnlink => CoverageClass::FsWrite,
            ClosedOperation::FsDeny => CoverageClass::FsDeny,
            ClosedOperation::NetConnect => CoverageClass::Net,
        }
    }
}

/// A coverage class (§11.4).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum CoverageClass {
    /// `proc.exec` and `proc.exit`.
    Exec,
    /// Mutating opens and every directory-entry variant.
    FsWrite,
    /// EACCES/EPERM results from the closed set, including connect.
    FsDeny,
    /// Audit-source connect results.
    Net,
    /// Proxy-source connect results, never pooled with audit counts.
    ProxyNet,
    /// Applied ceilings with a confirmed hit.
    Limits,
}

impl CoverageClass {
    /// Every class, in a stable order.
    pub const ALL: [CoverageClass; 6] = [
        CoverageClass::Exec,
        CoverageClass::FsWrite,
        CoverageClass::FsDeny,
        CoverageClass::Net,
        CoverageClass::ProxyNet,
        CoverageClass::Limits,
    ];

    /// The receipt key.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CoverageClass::Exec => "exec",
            CoverageClass::FsWrite => "fs.write",
            CoverageClass::FsDeny => "fs.deny",
            CoverageClass::Net => "net",
            CoverageClass::ProxyNet => "proxy.net",
            CoverageClass::Limits => "limits",
        }
    }

    /// The single source assigned to this class (§11.4).
    #[must_use]
    pub fn source(self) -> &'static str {
        match self {
            CoverageClass::Exec
            | CoverageClass::FsWrite
            | CoverageClass::FsDeny
            | CoverageClass::Net => "audit",
            CoverageClass::ProxyNet => "proxy",
            CoverageClass::Limits => "wrapper",
        }
    }
}

/// What one class established.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClassSummary {
    /// The class status.
    pub status: SourceStatus,
    /// Result count; meaningful only for an active class.
    pub observed_count: Option<u64>,
    /// Gaps affecting this class.
    pub gaps: Vec<Gap>,
}

impl ClassSummary {
    /// The honest summary for a class that is disabled or unimplemented.
    #[must_use]
    pub fn unsupported() -> Self {
        ClassSummary {
            status: SourceStatus::Unsupported,
            observed_count: None,
            gaps: Vec::new(),
        }
    }
}

/// Everything an observer backend reports at the end of an attempt.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CoverageSummary {
    /// The backend that ran, or null when none did.
    pub backend: Option<String>,
    /// The closed set identifier, or null.
    pub set: Option<String>,
    /// Whether attachment was established for this attempt.
    pub attached: bool,
    /// Per-source health.
    pub sources: SourceHealth,
    /// Bounded gap summaries for the observer as a whole.
    pub gaps: Vec<Gap>,
    /// Per-class summaries.
    pub classes: BTreeMap<CoverageClass, ClassSummary>,
}

impl CoverageSummary {
    /// The summary when nothing observed anything.
    ///
    /// The wrapper source is `supported`: this process exists and can state its
    /// own facts, but it has applied nothing. Every other source and every
    /// class is `unsupported` with a null count.
    #[must_use]
    pub fn unobserved() -> Self {
        CoverageSummary {
            backend: None,
            set: None,
            attached: false,
            sources: SourceHealth {
                wrapper: SourceStatus::Supported,
                audit: SourceStatus::Unsupported,
                proxy: SourceStatus::Unsupported,
            },
            gaps: Vec::new(),
            classes: CoverageClass::ALL
                .iter()
                .map(|class| (*class, ClassSummary::unsupported()))
                .collect(),
        }
    }

    /// The closed set this build implements on Linux.
    #[must_use]
    pub fn linux_closed_set() -> &'static str {
        CLOSED_SET_LINUX_V1
    }

    /// Renders the receipt's `observer` group.
    #[must_use]
    pub fn to_observer_record(&self) -> ObserverRecord {
        ObserverRecord {
            backend: self.backend.clone(),
            set: self.set.clone(),
            attached: self.attached,
            sources: self.sources,
            gaps: self.gaps.clone(),
        }
    }

    /// Renders the receipt's `coverage` group.
    ///
    /// A class this summary does not mention is `unsupported`, never an
    /// invented zero.
    #[must_use]
    pub fn to_coverage(&self) -> Coverage {
        let entry = |class: CoverageClass| -> CoverageEntry {
            let Some(summary) = self.classes.get(&class) else {
                return CoverageEntry::unsupported();
            };
            let sources = if summary.status == SourceStatus::Unsupported {
                Vec::new()
            } else {
                vec![class.source().to_owned()]
            };
            let observed_count = match summary.status {
                SourceStatus::Active => summary.observed_count,
                // §11.4: unsupported, degraded and supported-but-not-started
                // counts are null.
                _ => None,
            };
            CoverageEntry {
                status: summary.status,
                sources,
                observed_count,
                gaps: summary.gaps.clone(),
            }
        };
        Coverage {
            exec: entry(CoverageClass::Exec),
            fs_write: entry(CoverageClass::FsWrite),
            fs_deny: entry(CoverageClass::FsDeny),
            net: entry(CoverageClass::Net),
            limits: entry(CoverageClass::Limits),
            proxy_net: entry(CoverageClass::ProxyNet),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_denied_connect_counts_only_under_fs_deny() {
        assert_eq!(
            ClosedOperation::FsDeny.coverage_class(),
            CoverageClass::FsDeny
        );
        assert_eq!(
            ClosedOperation::NetConnect.coverage_class(),
            CoverageClass::Net
        );
    }

    #[test]
    fn every_directory_entry_operation_belongs_to_fs_write() {
        for operation in [
            ClosedOperation::FsCreate,
            ClosedOperation::FsWrite,
            ClosedOperation::FsRename,
            ClosedOperation::FsUnlink,
        ] {
            assert_eq!(operation.coverage_class(), CoverageClass::FsWrite);
        }
    }

    #[test]
    fn an_unobserved_attempt_has_no_counts_and_no_sources() {
        let coverage = CoverageSummary::unobserved().to_coverage();
        for entry in [
            &coverage.exec,
            &coverage.fs_write,
            &coverage.fs_deny,
            &coverage.net,
            &coverage.limits,
            &coverage.proxy_net,
        ] {
            assert_eq!(entry.status, SourceStatus::Unsupported);
            assert!(entry.sources.is_empty());
            assert_eq!(entry.observed_count, None);
        }
    }

    #[test]
    fn a_degraded_class_reports_a_null_count_even_when_one_was_offered() {
        let mut summary = CoverageSummary::unobserved();
        summary.classes.insert(
            CoverageClass::FsWrite,
            ClassSummary {
                status: SourceStatus::Degraded,
                observed_count: Some(7),
                gaps: Vec::new(),
            },
        );
        let coverage = summary.to_coverage();
        assert_eq!(coverage.fs_write.status, SourceStatus::Degraded);
        assert_eq!(
            coverage.fs_write.observed_count, None,
            "an incomplete interval has no count"
        );
        assert_eq!(coverage.fs_write.sources, vec!["audit".to_owned()]);
    }
}
