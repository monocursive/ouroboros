//! L05: an unobservable tree end must retain state, even after target exit.
use clap::Parser;
use ouro_jail::{capability::*, cli, config::EnvSettings, platform::*, records::*, supervisor};
use std::path::PathBuf;
use std::time::Duration;

mod common;

struct Unverifiable;
struct Prepared;
struct Running {
    confirmed: bool,
}

impl Platform for Unverifiable {
    fn owner_identity(&self) -> Option<OwnerIdentity> {
        Some(OwnerIdentity {
            pid: std::process::id(),
            boot_id: "00000000-0000-4000-8000-000000000001".into(),
            start_time_ticks: 1,
        })
    }
    fn identity(&self) -> PlatformIdentity {
        PlatformIdentity {
            os: Os::Linux,
            arch: "simulation".into(),
            kernel: "simulated-uninterruptible-tree".into(),
        }
    }
    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        plan.requirements
            .iter()
            .map(|name| Capability {
                name: name.clone(),
                status: CapabilityStatus::Available,
                scope: CapabilityScope::Tree,
                mechanism: Some("simulation".into()),
                reason_code: Some("ok".into()),
                measured_at: Some(rfc3339_utc(std::time::SystemTime::now())),
                evidence_ref: Some("L05 simulation".into()),
            })
            .collect()
    }
    fn prepare(
        &self,
        plan: PreparedPlan,
        _: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        std::fs::create_dir(plan.attempt_dir.join("scratch")).unwrap();
        std::fs::write(
            plan.attempt_dir.join("scratch/retained"),
            "a possibly live tree owns this",
        )
        .unwrap();
        Ok(Box::new(Prepared))
    }
}

impl PreparedExecution for Prepared {
    fn boundary(&self) -> BoundaryIdentity {
        BoundaryIdentity {
            boundary: "pid_namespace".into(),
            verification_scope: "attempt_tree".into(),
            native: Some(NativeLifetime {
                os: Os::Linux,
                details: Default::default(),
            }),
            process: None,
            backend: Some("simulation".into()),
            backend_version: Some("1".into()),
        }
    }
    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, JailError> {
        Ok(Box::new(Running { confirmed: false }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown { tree: None })
    }
}

impl RunningExecution for Running {
    fn wait(&mut self, _: Deadline) -> RunEvent {
        if !self.confirmed {
            self.confirmed = true;
            RunEvent::ExecConfirmed
        } else {
            RunEvent::TargetExited { code: 0 }
        }
    }
    fn request_stop(&mut self, _: StopReason) {}
    fn wait_tree(&mut self, budget: Duration) -> TreeObservation {
        assert_eq!(budget, Duration::from_secs(5));
        TreeObservation {
            tree_empty: None,
            verified_at: None,
            verification_scope: "attempt_tree".into(),
            integrity: "pending".into(),
        }
    }
    fn observer_summary(&mut self) -> Option<ouro_jail::observer::CoverageSummary> {
        None
    }
}

#[test]
fn l05_unknown_tree_retains_scratch_and_never_settles() {
    // Canonicalize to avoid macOS's /var -> /private/var alias in state paths.
    let root = common::private_tempdir();
    let root_path = root.path().canonicalize().unwrap();
    let workspace = root_path.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let cli::Command::Run(args) = cli::Cli::parse_from([
        "ouro-jail",
        "run",
        "--workspace",
        workspace.to_str().unwrap(),
        "--",
        "simulated-target",
    ])
    .command
    else {
        unreachable!()
    };
    let context = supervisor::Context {
        platform: Box::new(Unverifiable),
        env_settings: EnvSettings {
            config_dir: Some(root_path.join("config")),
            data_dir: Some(root_path.join("data")),
            ..Default::default()
        },
        cwd: workspace,
        home: None,
        env_lookup: Box::new(|_| None),
    };
    let report = supervisor::run(&context, &args);
    assert_ne!(report.exit_code, 0);
    assert_eq!(
        report.error.as_ref().unwrap().code,
        ErrorCode::TreeUnknown,
        "{:?}",
        report.error
    );
    let receipt = serde_json::to_value(report.receipt.unwrap()).unwrap();
    assert_ne!(receipt["phase"], "settled");
    assert_eq!(receipt["outcome"]["kind"], "exited");
    assert_eq!(receipt["outcome"]["code"], 0);
    assert_eq!(receipt["lifetime"]["tree_empty"], serde_json::Value::Null);
    assert_eq!(receipt["lifetime"]["verified_at"], serde_json::Value::Null);
    let attempt: PathBuf = report.receipt_path.unwrap().parent().unwrap().to_owned();
    assert!(attempt.join("scratch/retained").exists());
}
