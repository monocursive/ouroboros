//! J5-C review item 12: the observer's failure paths write receipts that
//! satisfy the frozen contract.
//!
//! §11.4 (jail-v1.md:1555-1558, :1636-1637): a degraded class states its
//! missing interval, and the frozen receipt schema requires a degraded class
//! to list at least one gap naming it. Two observer paths degraded classes
//! with no gap: the tracer thread panicking (every audit class), and a result
//! the trace could not take because its lock was poisoned. This file builds
//! the settled receipt each path produces, from the `AuditWriter` the product
//! uses, and holds it to the whole contract (`common::check_receipt`: the
//! schemas and `ouro_jail::records::semantic`). It needs no live kernel
//! feature, only the Linux build of the observer.

#![cfg(target_os = "linux")]

use std::time::{Duration, UNIX_EPOCH};

use ouro_jail::observer::CoverageSummary;
use ouro_jail::platform::linux::audit::AuditWriter;
use ouro_jail::platform::linux::tracer::{Args, ClosedOp, PathSnapshot, TracerSummary};
use ouro_jail::records::{
    Applied, AppliedFilesystem, AppliedLimit, AppliedMount, AppliedNetwork, AppliedSyscalls,
    AttemptRecord, Containment, ErrorCode, ErrorStage, EvidenceMode, JailError, JailRecord,
    Lifetime, NativeLifetime, NativeString, ObserveMode, Os, Outcome, OutcomeKind, Phase,
    PlatformRecord, PolicyRecord, ProcessIdentity, ProcessRecord, Remediation, StateCleanup,
    rfc3339_utc,
};

mod common;

/// A settled contained attempt whose observer account is `summary`, with the
/// `evidence_lost` error §11.4 makes of any degraded evidence class.
fn settled_receipt(summary: &CoverageSummary) -> serde_json::Value {
    let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut identity = serde_json::Map::new();
    identity.insert("boot_id".to_owned(), "fixture-boot".into());
    identity.insert("start_time_ticks".to_owned(), "123456".into());
    let lost = JailError::new(
        ErrorCode::EvidenceLost,
        ErrorStage::Reconciling,
        Remediation::InspectState,
        "coverage was lost by settlement",
    );
    let record = AttemptRecord {
        attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
        revision: 3,
        platform: PlatformRecord {
            os: Os::Linux,
            arch: "x86_64".to_owned(),
            kernel: "fixture-kernel".to_owned(),
        },
        jail: JailRecord {
            component: "ouro-jail".to_owned(),
            version: "0.0.0-test".to_owned(),
            backend: Some("bubblewrap".to_owned()),
            backend_version: Some("bubblewrap 0.11.1".to_owned()),
        },
        policy: PolicyRecord {
            name: "tool".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
            observe: ObserveMode::On,
            evidence: EvidenceMode::BestEffort,
            requirements: vec!["tree_termination".to_owned()],
            grants: Vec::new(),
        },
        containment: Containment::Enforced,
        exec_observed: true,
        argv_digest: Some(format!("sha256:{}", "b".repeat(64))),
        applied: Applied {
            filesystem: Some(AppliedFilesystem {
                mechanism: "bubblewrap".to_owned(),
                protected_coverage: "existing_and_root".to_owned(),
                mounts: vec![AppliedMount {
                    path: NativeString::Text("/work/space".to_owned()),
                    mode: "rw".to_owned(),
                }],
            }),
            network: AppliedNetwork {
                mode: "none".to_owned(),
                mechanism: Some("network_namespace".to_owned()),
                allowed_hosts: Vec::new(),
            },
            syscalls: Some(AppliedSyscalls {
                mechanism: "seccomp-bpf".to_owned(),
                digest: format!("sha256:{}", "c".repeat(64)),
            }),
            limits: vec![AppliedLimit {
                key: "wall".to_owned(),
                requested: "30m".to_owned(),
                required: true,
                applied: true,
                mechanism: Some("boottime-deadline".to_owned()),
                scope: Some("tree".to_owned()),
                hit: Some(false),
            }],
            environment_names: vec!["PATH".to_owned()],
            removed_environment_names: Vec::new(),
        },
        observer: summary.to_observer_record(),
        coverage: summary.to_coverage(),
        process: Some(ProcessRecord {
            pid: 1234,
            identity: ProcessIdentity {
                kind: "linux_boot_start".to_owned(),
                value: identity,
            },
        }),
        lifetime: Lifetime {
            boundary: "pid_namespace".to_owned(),
            native: Some(NativeLifetime {
                os: Os::Linux,
                details: serde_json::Map::new(),
            }),
            tree_empty: Some(true),
            verified_at: Some(rfc3339_utc(at)),
            verification_scope: Some("attempt_tree".to_owned()),
            integrity: "verified".to_owned(),
        },
        outcome: Outcome {
            kind: OutcomeKind::Exited,
            code: Some(0),
            signal: None,
            cause: None,
            error: None,
        },
        state_cleanup: StateCleanup::NotNeeded,
        cleanup_error: None,
        created_at: at,
        updated_at: at,
        errors: vec![lost.to_object()],
        credentials: Vec::new(),
    };
    serde_json::to_value(record.receipt(Phase::Settled)).expect("a receipt serializes")
}

/// A trace whose lock a panicking thread held.
fn poisoned_trace() -> ouro_jail::trace::SharedTrace {
    let file = tempfile::NamedTempFile::new().unwrap();
    let trace = ouro_jail::trace::shared(ouro_jail::trace::FileSink::new(file.reopen().unwrap()));
    let held = std::sync::Arc::clone(&trace);
    let _ = std::thread::spawn(move || {
        let _guard = held.lock().unwrap();
        panic!("poison the trace lock (test)");
    })
    .join();
    trace
}

#[test]
fn j5_a_panicked_observer_writes_a_receipt_that_passes_the_frozen_contract() {
    let writer = AuditWriter::new("att_test", None, b"/work/space", b"/tmp");
    let summary = writer.summary(
        &TracerSummary {
            thread_panicked: true,
            ..TracerSummary::default()
        },
        true,
    );
    let receipt = settled_receipt(&summary);
    common::check_receipt(&receipt)
        .unwrap_or_else(|error| panic!("{error}\n{:#}", receipt["coverage"]));
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        assert_eq!(receipt["coverage"][class]["status"], "degraded", "{class}");
    }
}

#[test]
fn j5_a_poisoned_trace_writes_a_receipt_that_passes_the_frozen_contract() {
    let mut writer = AuditWriter::new("att_test", Some(poisoned_trace()), b"/work/space", b"/tmp");
    writer.record_syscall(
        10,
        Some(1),
        10,
        ClosedOp::Open,
        "openat",
        &Args {
            path: Some(PathSnapshot {
                bytes: b"/work/space/f".to_vec(),
                complete: true,
            }),
            flags: Some(1),
            ..Args::default()
        },
        3,
    );
    let summary = writer.summary(&TracerSummary::default(), true);
    let receipt = settled_receipt(&summary);
    common::check_receipt(&receipt)
        .unwrap_or_else(|error| panic!("{error}\n{:#}", receipt["coverage"]));
    assert_eq!(receipt["coverage"]["fs.write"]["status"], "degraded");
}
