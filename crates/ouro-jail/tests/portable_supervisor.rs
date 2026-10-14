//! The supervisor's own guarantees over a simulated platform, natively on
//! every host: the §8.2 preparation budget crosses the platform seam, and
//! a claimed attempt always ends with a receipt (I01).
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser as _;
use ouro_jail::capability::{Capability, CapabilityScope, CapabilityStatus};
use ouro_jail::cli;
use ouro_jail::config::EnvSettings;
use ouro_jail::platform::{
    OwnerIdentity, PlanRequest, Platform, PlatformIdentity, PreparedExecution, PreparedPlan, Sinks,
};
use ouro_jail::records::{ErrorCode, ErrorStage, JailError, Os, Remediation, rfc3339_utc};
use ouro_jail::supervisor;

mod common;

/// A platform whose preparation always refuses, after recording what it
/// was given.
#[derive(Default)]
struct Sim {
    /// How long probing takes: time spent inside the preparation budget
    /// before `prepare` is reached.
    probe_delay: Duration,
    /// What `prepare` saw of the preparation budget.
    prepare_left: Arc<Mutex<Option<Duration>>>,
}

impl Platform for Sim {
    fn identity(&self) -> PlatformIdentity {
        PlatformIdentity {
            os: Os::Linux,
            arch: "simulation".into(),
            kernel: "simulated".into(),
        }
    }

    fn owner_identity(&self) -> Option<OwnerIdentity> {
        Some(OwnerIdentity {
            pid: std::process::id(),
            boot_id: "00000000-0000-4000-8000-000000000001".into(),
            start_time_ticks: 1,
        })
    }

    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        std::thread::sleep(self.probe_delay);
        plan.requirements
            .iter()
            .map(|name| Capability {
                name: name.clone(),
                status: CapabilityStatus::Available,
                scope: CapabilityScope::Tree,
                mechanism: Some("simulation".into()),
                reason_code: None,
                measured_at: Some(rfc3339_utc(std::time::SystemTime::now())),
                evidence_ref: None,
            })
            .collect()
    }

    fn prepare(
        &self,
        plan: PreparedPlan,
        _: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        *self.prepare_left.lock().unwrap() = Some(plan.prepare_deadline.remaining());
        Err(JailError::new(
            ErrorCode::BackendUnavailable,
            ErrorStage::Preparing,
            Remediation::HostSetup,
            "the simulation prepares nothing".to_owned(),
        ))
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    workspace: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = common::private_tempdir();
        let root = dir.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        Fixture {
            _root: dir,
            root,
            workspace,
        }
    }

    fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    fn run(&self, sim: Sim) -> supervisor::RunReport {
        let cli::Command::Run(args) = cli::Cli::parse_from([
            "ouro-jail",
            "run",
            "--workspace",
            self.workspace.to_str().unwrap(),
            "--",
            "simulated-target",
        ])
        .command
        else {
            unreachable!()
        };
        let context = supervisor::Context {
            platform: Box::new(sim),
            env_settings: EnvSettings {
                config_dir: Some(self.root.join("config")),
                data_dir: Some(self.data()),
                ..Default::default()
            },
            cwd: self.workspace.clone(),
            home: None,
            env_lookup: Box::new(|_| None),
        };
        supervisor::run(&context, &args)
    }
}

/// §8.2: the 30-second preparation budget covers steps 1 to 5. The
/// platform's steps 3 to 5 get what resolution, the claim and probing left
/// of it, not a fresh 30 seconds of their own.
#[test]
fn the_platform_prepares_within_what_is_left_of_the_supervisors_budget() {
    let fixture = Fixture::new();
    let prepare_left = Arc::new(Mutex::new(None));
    let probe_delay = Duration::from_millis(300);
    let report = fixture.run(Sim {
        probe_delay,
        prepare_left: Arc::clone(&prepare_left),
    });
    assert_eq!(
        report.error.as_ref().map(|error| error.code),
        Some(ErrorCode::BackendUnavailable),
        "{:?}",
        report.error
    );
    let left = prepare_left.lock().unwrap().expect("prepare ran");
    assert!(
        left <= supervisor::PREPARE_BUDGET - probe_delay,
        "the platform was given {left:?}, more than the {:?} probing left",
        supervisor::PREPARE_BUDGET - probe_delay
    );
    assert!(
        left > supervisor::PREPARE_BUDGET / 2,
        "the budget is the supervisor's, not an expired one: {left:?}"
    );
}
