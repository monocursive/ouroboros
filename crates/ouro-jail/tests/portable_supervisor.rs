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
    /// A state root whose attempts get a directory planted at
    /// `trace.ndjson` while the supervisor claims them: a trace file that
    /// can no longer be created once the claim exists.
    plant_trace_dir_under: Option<PathBuf>,
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
        // The claim reads the owner's identity just before it publishes.
        if let Some(data) = &self.plant_trace_dir_under
            && let Ok(entries) = std::fs::read_dir(data.join("attempts"))
        {
            for entry in entries.flatten() {
                let _ = std::fs::create_dir(entry.path().join("trace.ndjson"));
            }
        }
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

    fn attempts(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.data().join("attempts"))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default()
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
        ..Sim::default()
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

/// I01: an attempt that is claimed always ends with a receipt. The output
/// channels a refusal needs are opened before the claim, so a trace file
/// that cannot be created at the claim's moment can no longer leave a
/// claimed attempt with nothing to say what became of it.
#[test]
fn a_claimed_attempt_always_has_a_receipt() {
    let fixture = Fixture::new();
    let report = fixture.run(Sim {
        plant_trace_dir_under: Some(fixture.data()),
        ..Sim::default()
    });
    let attempts = fixture.attempts();
    assert_eq!(attempts.len(), 1, "{attempts:?}");
    let attempt = &attempts[0];
    if !attempt.join("jail-state.json").exists() {
        // Refused before the claim: nothing was claimed, nothing is owed.
        assert!(report.receipt.is_none());
        return;
    }
    let receipt_path = attempt.join("jail.json");
    assert!(
        receipt_path.exists(),
        "a claimed attempt has no receipt; the run reported {:?}",
        report.error
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["phase"], "refused", "{receipt:#}");
    common::assert_semantic_receipt(&receipt);
}

/// §14.1: plain `doctor` reports the host; only `--launch` has credential
/// sources whose placement against the writable grants it must judge, so a
/// grant it cannot inspect is no reason for plain `doctor` to fail.
#[test]
fn plain_doctor_never_inspects_credential_placement() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = Fixture::new();
    let config = fixture.root.join("config");
    std::fs::create_dir(&config).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sealed = fixture.root.join("sealed");
    std::fs::create_dir_all(sealed.join("inner")).unwrap();
    let config_file = config.join("config.toml");
    std::fs::write(
        &config_file,
        format!(
            "[jail.filesystem]\nread_write = [{:?}]\n",
            sealed.join("inner").display().to_string()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&config_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    // The grant's parent cannot be searched, so its identity cannot be read.
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let context = supervisor::Context {
        platform: Box::new(Sim::default()),
        env_settings: EnvSettings {
            config_dir: Some(config),
            data_dir: Some(fixture.data()),
            ..Default::default()
        },
        cwd: fixture.workspace.clone(),
        home: None,
        env_lookup: Box::new(|_| None),
    };
    let cli::Command::Doctor(args) = cli::Cli::parse_from([
        "ouro-jail",
        "doctor",
        "--workspace",
        fixture.workspace.to_str().unwrap(),
    ])
    .command
    else {
        unreachable!()
    };
    let result = supervisor::doctor(&context, &args);
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
    let report = result.unwrap_or_else(|error| panic!("plain doctor refused: {error:?}"));
    assert!(report.launch.is_none());
}
