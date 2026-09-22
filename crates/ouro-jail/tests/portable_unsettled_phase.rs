//! §8.1 / §13.2: an attempt that ends unsettled keeps its last nonsettled
//! phase, and `enforced` is the phase after a confirmed target exec. A run
//! whose target ended before any exec confirmation stays `prepared`, whatever
//! the profile: the end-of-run code is shared. Simulated platform, portable.
use clap::Parser;
use jsonschema::{Registry, Resource, Validator};
use ouro_jail::{capability::*, cli, config::EnvSettings, platform::*, records::*, supervisor};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

mod common;

/// What the simulated run does.
#[derive(Clone, Copy)]
struct Script {
    /// Report the exec confirmation before the end.
    confirm_exec: bool,
    /// The integrity tree verification ends with.
    integrity: &'static str,
}

struct Simulated(Script);
struct Prepared(Script);
struct Running {
    script: Script,
    step: u8,
}

impl Platform for Simulated {
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
                measured_at: Some(rfc3339_utc(std::time::SystemTime::now())),
                evidence_ref: Some("phase simulation".into()),
            })
            .collect()
    }
    fn prepare(&self, _: PreparedPlan, _: Sinks) -> Result<Box<dyn PreparedExecution>, JailError> {
        Ok(Box::new(Prepared(self.0)))
    }
}

impl PreparedExecution for Prepared {
    fn boundary(&self) -> BoundaryIdentity {
        BoundaryIdentity {
            boundary: "supervisor_cgroup".into(),
            verification_scope: "registered_boundary".into(),
            native: Some(NativeLifetime {
                os: Os::Linux,
                details: Default::default(),
            }),
            process: Some(ProcessRecord {
                pid: 4242,
                identity: ProcessIdentity {
                    kind: "linux_boot_start".into(),
                    value: Default::default(),
                },
            }),
            backend: Some("none".into()),
            backend_version: None,
        }
    }
    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, JailError> {
        Ok(Box::new(Running {
            script: self.0,
            step: 0,
        }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown { tree: None })
    }
}

impl RunningExecution for Running {
    fn wait(&mut self, _: Deadline) -> RunEvent {
        self.step += 1;
        match (self.step, self.script.confirm_exec) {
            (1, true) => RunEvent::ExecConfirmed,
            (_, true) => RunEvent::TargetSignaled { signal: 9 },
            // A signal death with no independent evidence of exec.
            (_, false) => RunEvent::Unknown {
                reason: "the target ended by a signal before its exec was confirmed".into(),
            },
        }
    }
    fn request_stop(&mut self, _: StopReason) {}
    fn wait_tree(&mut self, _: Duration) -> TreeObservation {
        TreeObservation {
            tree_empty: None,
            verified_at: None,
            verification_scope: "registered_boundary".into(),
            integrity: self.script.integrity.into(),
        }
    }
    fn observer_summary(&mut self) -> Option<ouro_jail::observer::CoverageSummary> {
        None
    }
}

fn receipt_validator() -> Validator {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/jail-v1");
    let mut resources = Vec::new();
    let mut receipt = None;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".schema.json") {
            continue;
        }
        let schema: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        if name == "jail-receipt.schema.json" {
            receipt = Some(schema.clone());
        }
        let id = schema["$id"].as_str().unwrap().to_owned();
        resources.push((id, Resource::from_contents(schema)));
    }
    let registry: &'static Registry = Box::leak(Box::new(
        Registry::new()
            .extend(resources)
            .unwrap()
            .prepare()
            .unwrap(),
    ));
    jsonschema::options()
        .with_registry(registry)
        .should_validate_formats(true)
        .build(&receipt.unwrap())
        .unwrap()
}

fn run(script: Script) -> Value {
    let root = common::private_tempdir();
    let root_path = root.path().canonicalize().unwrap();
    let workspace = root_path.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let cli::Command::Run(args) = cli::Cli::parse_from([
        "ouro-jail",
        "run",
        "--profile",
        "none",
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
        platform: Box::new(Simulated(script)),
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
    assert_eq!(
        report.error.as_ref().map(|error| error.code),
        Some(ErrorCode::TreeUnknown),
        "{:?}",
        report.error
    );
    let receipt = serde_json::to_value(report.receipt.unwrap()).unwrap();
    receipt_validator()
        .validate(&receipt)
        .unwrap_or_else(|error| panic!("the receipt fails its schema: {error}\n{receipt:#}"));
    receipt
}

#[test]
fn an_unsettled_end_without_a_confirmed_exec_stays_prepared() {
    for (integrity, expected) in [("pending", "verified"), ("lost", "lost")] {
        let receipt = run(Script {
            confirm_exec: false,
            integrity,
        });
        assert_eq!(receipt["phase"], "prepared", "{integrity}: {receipt:#}");
        assert_eq!(receipt["exec_observed"], false);
        assert_eq!(receipt["outcome"]["kind"], "unknown");
        assert_eq!(receipt["lifetime"]["tree_empty"], Value::Null);
        // An unknown end keeps the prepared verification; a loss stays lost.
        assert_eq!(receipt["lifetime"]["integrity"], expected, "{integrity}");
    }
}

#[test]
fn an_unsettled_end_after_a_confirmed_exec_stays_enforced() {
    let receipt = run(Script {
        confirm_exec: true,
        integrity: "lost",
    });
    assert_eq!(receipt["phase"], "enforced", "{receipt:#}");
    assert_eq!(receipt["exec_observed"], true);
    assert_eq!(receipt["outcome"]["kind"], "signaled");
    assert_eq!(receipt["lifetime"]["integrity"], "lost");
}
