//! J5-B1, portable: what the jail library must not do to the process that
//! hosts it.
//!
//! `ouro-jail run` gives the caller EOF on stdout once the target closes it
//! by pointing the supervisor's own stdout at `/dev/null` after preparation
//! (§8.3, X05.3). That is a decision for the `ouro-jail` binary, whose stdout
//! is the target's: a program that calls the library in-process (§16: "The
//! future `ouro` executable can call the jail library in-process") keeps its
//! own stdout. These tests run a whole attempt in-process over a scripted
//! platform, on Linux and macOS alike.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use clap::Parser as _;
use ouro_jail::capability::{Capability, CapabilityScope, CapabilityStatus};
use ouro_jail::cli;
use ouro_jail::config::EnvSettings;
use ouro_jail::platform::{
    BoundaryIdentity, Deadline, OwnerIdentity, PlanRequest, Platform, PlatformIdentity,
    PreparedExecution, PreparedPlan, RunEvent, RunningExecution, Sinks, StopReason, Teardown,
    TreeObservation,
};
use ouro_jail::records::{JailError, NativeLifetime, Os, rfc3339_utc};
use ouro_jail::supervisor;

mod common;

/// A platform whose boundary is scripted: every requirement is available,
/// the target execs and exits 0, and the tree is verified empty.
struct Scripted;

fn verified_tree() -> TreeObservation {
    TreeObservation {
        tree_empty: Some(true),
        verified_at: Some(SystemTime::now()),
        verification_scope: "attempt_tree".into(),
        integrity: "verified".into(),
    }
}

impl Platform for Scripted {
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
            kernel: "simulated".into(),
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
                measured_at: Some(rfc3339_utc(SystemTime::now())),
                evidence_ref: Some("J5-B1 in-process simulation".into()),
            })
            .collect()
    }
    fn prepare(&self, _: PreparedPlan, _: Sinks) -> Result<Box<dyn PreparedExecution>, JailError> {
        Ok(Box::new(ScriptedPrepared))
    }
}

struct ScriptedPrepared;

impl PreparedExecution for ScriptedPrepared {
    fn boundary(&self) -> BoundaryIdentity {
        BoundaryIdentity {
            boundary: "pid_namespace".into(),
            verification_scope: "attempt_tree".into(),
            native: Some(NativeLifetime {
                os: Os::Linux,
                details: serde_json::Map::default(),
            }),
            process: None,
            backend: Some("simulation".into()),
            backend_version: Some("1".into()),
        }
    }
    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, JailError> {
        Ok(Box::new(ScriptedRunning { step: 0 }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown {
            tree: Some(verified_tree()),
        })
    }
    fn release_reporting_teardown(
        self: Box<Self>,
    ) -> Result<Box<dyn RunningExecution>, Box<ouro_jail::platform::ReleaseFailure>> {
        self.release().map_err(|error| {
            Box::new(ouro_jail::platform::ReleaseFailure {
                error,
                teardown: None,
            })
        })
    }
}

struct ScriptedRunning {
    step: u8,
}

impl RunningExecution for ScriptedRunning {
    fn wait(&mut self, _: Deadline) -> RunEvent {
        self.step += 1;
        if self.step == 1 {
            RunEvent::ExecConfirmed
        } else {
            RunEvent::TargetExited { code: 0 }
        }
    }
    fn request_stop(&mut self, _: StopReason) {}
    fn wait_tree(&mut self, _: Duration) -> TreeObservation {
        verified_tree()
    }
    fn observer_summary(&mut self) -> Option<ouro_jail::observer::CoverageSummary> {
        None
    }
}

/// The `(dev, ino)` of what this process's descriptor 1 refers to.
fn stdout_identity() -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    let path = if Path::new("/dev/fd/1").exists() {
        PathBuf::from("/dev/fd/1")
    } else {
        PathBuf::from("/proc/self/fd/1")
    };
    let metadata = std::fs::metadata(path).expect("descriptor 1 can be inspected");
    (metadata.dev(), metadata.ino())
}

/// One whole attempt, in this process, through `supervisor::run`.
fn run_in_process() -> supervisor::RunReport {
    use std::os::unix::fs::PermissionsExt as _;
    let temp = common::private_tempdir();
    let root = std::fs::canonicalize(temp.path()).expect("canonical");
    for name in ["config", "data", "workspace"] {
        std::fs::create_dir(root.join(name)).expect("a directory");
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o700))
            .expect("private");
    }
    let workspace = root.join("workspace");
    let cli::Command::Run(args) = cli::Cli::parse_from([
        "ouro-jail".to_owned(),
        "run".to_owned(),
        "--workspace".to_owned(),
        workspace.display().to_string(),
        "--".to_owned(),
        "simulated-target".to_owned(),
    ])
    .command
    else {
        unreachable!("`run` parses as the run command")
    };
    let ctx = supervisor::Context {
        platform: Box::new(Scripted),
        env_settings: EnvSettings {
            config_dir: Some(root.join("config")),
            data_dir: Some(root.join("data")),
            ..EnvSettings::default()
        },
        cwd: workspace,
        home: Some(root.join("home")),
        env_lookup: Box::new(|_| None),
    };
    let report = supervisor::run(&ctx, &args);
    drop(temp);
    report
}

/// X05.3's stdout release is the binary's, not the library's: a whole
/// attempt run in-process leaves the host's descriptor 1 on the object it
/// was on. (It used to be pointed at `/dev/null` by the library itself, which
/// silently swallowed the output of every in-process caller after its first
/// run, this test binary included.)
#[test]
fn an_in_process_run_leaves_the_hosts_stdout_where_it_was() {
    let before = stdout_identity();
    let report = run_in_process();
    assert_eq!(
        report.exit_code, 0,
        "the scripted attempt did not run to its end: {:?}",
        report.error
    );
    assert!(
        report.receipt.is_some(),
        "the attempt reached no receipt, so preparation was never passed"
    );
    assert_eq!(
        stdout_identity(),
        before,
        "running an attempt in-process moved this process's stdout"
    );
}
