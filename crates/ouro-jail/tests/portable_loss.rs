//! J4 slice L, portable half: what the supervisor does with an evidence loss
//! (jail-v1 §11.4, §6.4, §13.2; acceptance R04).
//!
//! - Strict evidence stops the attempt: the loss is the stop, and the target
//!   that would otherwise run on is ended by it.
//! - Best-effort evidence runs the target to its own end, keeps the degraded
//!   coverage and the loss in `errors[]`, and the jail exits 1.
//! - The first stop cause wins (§6.4): a later loss, or a later deadline, is
//!   recorded but does not replace it.
//! - Loss never changes a protection label: `containment` and
//!   `child_protection` read the same in every receipt revision of the
//!   attempt, before and after the loss, in either evidence mode.
//!
//! The platform is simulated and the filesystem is real, so every receipt
//! revision the supervisor persists can be read back as it is written. The
//! simulated target never ends by itself while a stop is still possible: it
//! ends when the supervisor stops it, or, when nothing does, only after a
//! long run of polls — which is how "ran to its end" is told apart from
//! "was stopped".

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use clap::Parser as _;
use jsonschema::{Registry, Resource, Validator};
use ouro_jail::capability::{Capability, CapabilityScope, CapabilityStatus};
use ouro_jail::config::EnvSettings;
use ouro_jail::observer::{ClassSummary, CoverageClass, CoverageSummary};
use ouro_jail::platform::{
    BoundaryIdentity, Deadline, OwnerIdentity, PlanRequest, Platform, PlatformIdentity,
    PreparedExecution, PreparedPlan, RunEvent, RunningExecution, Sinks, StopReason, Teardown,
    TreeObservation,
};
use ouro_jail::records::{
    Applied, AppliedFilesystem, AppliedNetwork, AppliedSyscalls, CLOSED_SET_LINUX_V1, ErrorCode,
    Gap, NativeLifetime, Os, ProcessIdentity, ProcessRecord, SourceHealth, SourceStatus,
    rfc3339_utc,
};
use ouro_jail::{cli, supervisor};
use serde_json::Value;

mod common;

// ---------------------------------------------------------------------------
// A scripted platform whose target runs until something stops it
// ---------------------------------------------------------------------------

/// Polls the simulated target survives when nothing stops it. Far beyond
/// anything the supervisor needs to act on an event it has already been
/// handed, so reaching it means the supervisor did not stop the target.
const NATURAL_END_POLLS: u32 = 2_000;

/// What the simulated run reports once released.
#[derive(Clone)]
struct Script {
    /// Reported in order, one per `wait`, before the target's own end.
    events: Vec<RunEvent>,
    /// Where the supervisor keeps its attempts, so each receipt revision
    /// can be read as it is persisted.
    data: PathBuf,
    /// The coverage the observer reports at the end.
    coverage: CoverageSummary,
    /// Every `request_stop` the supervisor made, in order.
    stops: Arc<Mutex<Vec<StopReason>>>,
    /// `(phase, containment, child_protection)` of every receipt revision
    /// seen on disk, in order, duplicates removed.
    labels: Arc<Mutex<Vec<(String, String, String)>>>,
    /// A contained boundary (`tool`): a pid namespace verified over the
    /// attempt tree, with an application of the shape the contract requires.
    contained: bool,
}

struct Simulated(Script);
struct Prepared(Script);
struct Running {
    events: VecDeque<RunEvent>,
    script: Script,
    polls: u32,
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
                measured_at: Some(rfc3339_utc(SystemTime::now())),
                evidence_ref: Some("loss simulation".into()),
            })
            .collect()
    }
    fn prepare(
        &self,
        _: PreparedPlan,
        _: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, ouro_jail::records::JailError> {
        Ok(Box::new(Prepared(self.0.clone())))
    }
}

/// The verification scope of the simulated boundary.
fn scope(contained: bool) -> &'static str {
    if contained {
        "attempt_tree"
    } else {
        "registered_boundary"
    }
}

impl PreparedExecution for Prepared {
    fn boundary(&self) -> BoundaryIdentity {
        BoundaryIdentity {
            boundary: if self.0.contained {
                "pid_namespace"
            } else {
                "supervisor_cgroup"
            }
            .into(),
            verification_scope: scope(self.0.contained).into(),
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
            backend: Some("simulated".into()),
            backend_version: None,
        }
    }
    fn applied(&self) -> Option<Applied> {
        // `none` applies nothing but the supervisor's own wall; a contained
        // boundary says what it applied, and says it was simulated.
        self.0.contained.then(|| Applied {
            filesystem: Some(AppliedFilesystem {
                mechanism: "simulation".into(),
                protected_coverage: "none".into(),
                mounts: Vec::new(),
            }),
            network: AppliedNetwork {
                mode: "none".into(),
                mechanism: Some("simulation".into()),
                allowed_hosts: Vec::new(),
            },
            syscalls: Some(AppliedSyscalls {
                mechanism: "simulation".into(),
                digest: ouro_jail::canonical::sha256_prefixed(b"simulation"),
            }),
            limits: Vec::new(),
            environment_names: Vec::new(),
            removed_environment_names: Vec::new(),
        })
    }
    fn release(
        self: Box<Self>,
    ) -> Result<Box<dyn RunningExecution>, ouro_jail::records::JailError> {
        Ok(Box::new(Running {
            events: self.0.events.clone().into(),
            script: self.0,
            polls: 0,
        }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, ouro_jail::records::JailError> {
        Ok(Teardown { tree: None })
    }
}

impl Running {
    /// Reads the attempt's current receipt, if one is on disk yet, and keeps
    /// its protection labels.
    fn note_labels(&self) {
        let Ok(entries) = std::fs::read_dir(self.script.data.join("attempts")) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(text) = std::fs::read_to_string(entry.path().join("jail.json")) else {
                continue;
            };
            let Ok(receipt) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            let seen = (
                receipt["phase"].as_str().unwrap_or("?").to_owned(),
                receipt["containment"].as_str().unwrap_or("?").to_owned(),
                receipt["child_protection"]
                    .as_str()
                    .unwrap_or("?")
                    .to_owned(),
            );
            let mut labels = self.script.labels.lock().unwrap();
            if labels.last() != Some(&seen) {
                labels.push(seen);
            }
        }
    }
}

impl RunningExecution for Running {
    fn wait(&mut self, _: Deadline) -> RunEvent {
        self.note_labels();
        if let Some(event) = self.events.pop_front() {
            return event;
        }
        // Stopped: the target dies of the cooperative SIGTERM.
        if !self.script.stops.lock().unwrap().is_empty() {
            return RunEvent::TargetSignaled { signal: 15 };
        }
        // Nothing stopped it: it runs on, and ends by itself eventually.
        self.polls += 1;
        if self.polls >= NATURAL_END_POLLS {
            return RunEvent::TargetExited { code: 0 };
        }
        RunEvent::Poll
    }
    fn request_stop(&mut self, reason: StopReason) {
        self.script.stops.lock().unwrap().push(reason);
    }
    fn wait_tree(&mut self, _: Duration) -> TreeObservation {
        self.note_labels();
        TreeObservation {
            tree_empty: Some(true),
            verified_at: Some(SystemTime::now()),
            verification_scope: scope(self.script.contained).into(),
            integrity: "verified".into(),
        }
    }
    fn observer_summary(&mut self) -> Option<CoverageSummary> {
        Some(self.script.coverage.clone())
    }
}

// ---------------------------------------------------------------------------
// What a ptrace observer reports after one abandoned open
// ---------------------------------------------------------------------------

/// Exact counts the untouched classes carry.
const EXEC_COUNT: u64 = 4;
const NET_COUNT: u64 = 3;

/// The account a Linux observer gives after a thread parked in an open was
/// destroyed by a sibling's exec: one `entry_abandoned` gap naming the open's
/// classes, `fs.write` and `fs.deny` degraded with null counts, `exec` and
/// `net` still exact. (The count offered for a degraded class is deliberately
/// not null here: the receipt must null it whatever the backend offers.)
fn degraded_coverage() -> CoverageSummary {
    let gap = Gap {
        classes: vec!["fs.deny".into(), "fs.write".into()],
        source: "audit".into(),
        start_ns: "1000".into(),
        end_ns: Some("2000".into()),
        reason: "entry_abandoned".into(),
        lost_count: Some(1),
    };
    let active = |count| ClassSummary {
        status: SourceStatus::Active,
        observed_count: Some(count),
        gaps: Vec::new(),
    };
    let degraded = ClassSummary {
        status: SourceStatus::Degraded,
        observed_count: Some(7),
        gaps: vec![gap.clone()],
    };
    let mut summary = CoverageSummary::unobserved();
    summary.backend = Some("ptrace".into());
    summary.set = Some(CLOSED_SET_LINUX_V1.into());
    summary.attached = true;
    summary.sources = SourceHealth {
        wrapper: SourceStatus::Active,
        audit: SourceStatus::Degraded,
        proxy: SourceStatus::Unsupported,
    };
    summary.gaps = vec![gap];
    summary
        .classes
        .insert(CoverageClass::Exec, active(EXEC_COUNT));
    summary
        .classes
        .insert(CoverageClass::FsWrite, degraded.clone());
    summary.classes.insert(CoverageClass::FsDeny, degraded);
    summary
        .classes
        .insert(CoverageClass::Net, active(NET_COUNT));
    summary.classes.insert(CoverageClass::Limits, active(0));
    summary
}

fn evidence_lost() -> RunEvent {
    RunEvent::EvidenceLost {
        reason: "the closed-set observer lost coverage: entry_abandoned".into(),
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    _root: tempfile::TempDir,
    config: PathBuf,
    data: PathBuf,
    workspace: PathBuf,
    home: PathBuf,
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

struct Outcome {
    report: supervisor::RunReport,
    receipt: Value,
    stops: Vec<StopReason>,
    labels: Vec<(String, String, String)>,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = common::private_tempdir();
        // Canonical, so that macOS's /var -> /private/var alias is not a
        // symlink on any no-follow walk.
        let root = dir.path().canonicalize().unwrap();
        let fixture = Fixture {
            config: root.join("config"),
            data: root.join("data"),
            workspace: root.join("workspace"),
            home: root.join("home"),
            _root: dir,
        };
        for path in [&fixture.config, &fixture.data, &fixture.workspace] {
            private_dir(path);
        }
        fixture
    }

    fn run(&self, events: Vec<RunEvent>, flags: &[&str]) -> Outcome {
        let script = Script {
            events,
            data: self.data.clone(),
            coverage: degraded_coverage(),
            stops: Arc::default(),
            labels: Arc::default(),
            contained: flags.contains(&"tool"),
        };
        let stops = Arc::clone(&script.stops);
        let labels = Arc::clone(&script.labels);
        let context = supervisor::Context {
            platform: Box::new(Simulated(script)),
            env_settings: EnvSettings {
                config_dir: Some(self.config.clone()),
                data_dir: Some(self.data.clone()),
                ..Default::default()
            },
            cwd: self.workspace.clone(),
            home: Some(self.home.clone()),
            env_lookup: Box::new(|_| None),
        };
        let mut argv: Vec<String> = vec!["ouro-jail".into(), "run".into()];
        argv.push("--workspace".into());
        argv.push(self.workspace.display().to_string());
        argv.extend(flags.iter().map(|flag| (*flag).to_owned()));
        argv.push("--".into());
        argv.push("simulated-target".into());
        let cli::Command::Run(args) = cli::Cli::parse_from(argv).command else {
            unreachable!()
        };
        let report = supervisor::run(&context, &args);
        let receipt = valid_receipt(&report);
        let stops = stops.lock().unwrap().clone();
        let mut labels = labels.lock().unwrap().clone();
        let settled = (
            receipt["phase"].as_str().unwrap_or("?").to_owned(),
            receipt["containment"].as_str().unwrap_or("?").to_owned(),
            receipt["child_protection"]
                .as_str()
                .unwrap_or("?")
                .to_owned(),
        );
        if labels.last() != Some(&settled) {
            labels.push(settled);
        }
        Outcome {
            report,
            receipt,
            stops,
            labels,
        }
    }
}

fn receipt_validator() -> &'static Validator {
    static ONCE: std::sync::OnceLock<Validator> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
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
            let schema: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
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
    })
}

fn valid_receipt(report: &supervisor::RunReport) -> Value {
    let receipt = serde_json::to_value(
        report
            .receipt
            .as_ref()
            .unwrap_or_else(|| panic!("a receipt; the run ended with {:?}", report.error)),
    )
    .unwrap();
    let errors: Vec<String> = receipt_validator()
        .iter_errors(&receipt)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "the receipt fails its schema: {errors:?}\n{receipt:#}"
    );
    receipt
}

fn error_codes(receipt: &Value) -> Vec<String> {
    receipt["errors"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|error| error["code"].as_str().map(str::to_owned))
        .collect()
}

/// The coverage the receipt renders from the observer's account: affected
/// classes degraded with null counts and the gap named; untouched classes
/// with their exact counts.
fn assert_coverage_is_honest(receipt: &Value) {
    let coverage = &receipt["coverage"];
    for class in ["fs.write", "fs.deny"] {
        let entry = &coverage[class];
        assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
        assert_eq!(
            entry["observed_count"],
            Value::Null,
            "{class}: a degraded class has no count: {entry:#}"
        );
        assert!(
            entry["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|gap| gap["reason"] == "entry_abandoned"),
            "{class}: {entry:#}"
        );
    }
    assert_eq!(coverage["exec"]["status"], "active", "{coverage:#}");
    assert_eq!(coverage["exec"]["observed_count"], EXEC_COUNT);
    assert_eq!(coverage["net"]["status"], "active", "{coverage:#}");
    assert_eq!(coverage["net"]["observed_count"], NET_COUNT);
    assert_eq!(receipt["observer"]["sources"]["audit"], "degraded");
    assert_eq!(receipt["observer"]["attached"], true);
}

// ---------------------------------------------------------------------------
// R04
// ---------------------------------------------------------------------------

/// Strict: the loss stops the attempt. The target would run for
/// `NATURAL_END_POLLS` more polls; it is stopped instead, the stop is the
/// loss, and the jail exits 1 with `evidence_lost`.
#[test]
fn j4_r04_strict_stops() {
    for profile in ["none", "tool"] {
        let fixture = Fixture::new();
        let run = fixture.run(
            vec![RunEvent::ExecConfirmed, RunEvent::Poll, evidence_lost()],
            &["--profile", profile, "--evidence", "strict"],
        );
        assert_eq!(
            run.stops,
            vec![StopReason::EvidenceLoss],
            "{profile}: strict evidence stops the attempt for the loss, once"
        );
        let outcome = &run.receipt["outcome"];
        assert_eq!(outcome["kind"], "signaled", "{profile}: {outcome:#}");
        assert_eq!(outcome["signal"], 15, "{profile}: {outcome:#}");
        assert_eq!(outcome["cause"], "evidence_loss", "{profile}: {outcome:#}");
        assert_eq!(run.receipt["phase"], "settled");
        assert_eq!(run.report.exit_code, 1, "{profile}: a loss is a tool error");
        assert_eq!(
            run.report.error.as_ref().map(|error| error.code),
            Some(ErrorCode::EvidenceLost),
            "{profile}"
        );
        assert!(
            error_codes(&run.receipt).contains(&"evidence_lost".to_owned()),
            "{profile}: {:#}",
            run.receipt["errors"]
        );
        assert_coverage_is_honest(&run.receipt);
    }
}

/// Best-effort: the same loss stops nothing. The target runs to its own end
/// (exit 0, no cause), the receipt keeps the degraded coverage and the
/// loss, and the jail itself exits 1.
#[test]
fn j4_r04_best_effort_runs_to_the_end_degraded_exits_1() {
    for profile in ["none", "tool"] {
        let fixture = Fixture::new();
        let run = fixture.run(
            vec![RunEvent::ExecConfirmed, RunEvent::Poll, evidence_lost()],
            &["--profile", profile, "--evidence", "best-effort"],
        );
        assert!(
            run.stops.is_empty(),
            "{profile}: best-effort evidence never stops for a loss: {:?}",
            run.stops
        );
        let outcome = &run.receipt["outcome"];
        assert_eq!(outcome["kind"], "exited", "{profile}: {outcome:#}");
        assert_eq!(outcome["code"], 0, "{profile}: {outcome:#}");
        assert_eq!(
            outcome["cause"],
            Value::Null,
            "{profile}: nothing stopped the target: {outcome:#}"
        );
        assert_eq!(run.receipt["phase"], "settled");
        assert_eq!(
            run.report.exit_code, 1,
            "{profile}: the child exited 0, the jail exits 1 for the loss"
        );
        assert_eq!(
            run.report.error.as_ref().map(|error| error.code),
            Some(ErrorCode::EvidenceLost),
            "{profile}"
        );
        assert!(
            error_codes(&run.receipt).contains(&"evidence_lost".to_owned()),
            "{profile}: {:#}",
            run.receipt["errors"]
        );
        assert_coverage_is_honest(&run.receipt);
    }
}

/// The first stop cause wins (§6.4). A deadline first, then two losses under
/// strict: the cause stays `wall_expiry`, the platform was asked to stop
/// for the deadline first, and both losses are still recorded. A loss first,
/// then a second loss and a deadline: the cause stays `evidence_loss` and
/// the deadline is its limit's hit. Under best-effort a loss is never a
/// cause, so a later deadline is.
#[test]
fn j4_r04_later_loss_keeps_first_cause() {
    let fixture = Fixture::new();
    let run = fixture.run(
        vec![
            RunEvent::ExecConfirmed,
            RunEvent::WallExpired,
            evidence_lost(),
            evidence_lost(),
        ],
        &[
            "--profile",
            "none",
            "--evidence",
            "strict",
            "--limit",
            "wall=1h",
        ],
    );
    assert_eq!(run.stops.first(), Some(&StopReason::WallExpiry));
    assert_eq!(
        run.receipt["outcome"]["cause"], "wall_expiry",
        "{:#}",
        run.receipt["outcome"]
    );
    let losses = error_codes(&run.receipt)
        .iter()
        .filter(|code| *code == "evidence_lost")
        .count();
    assert_eq!(losses, 2, "each later loss is recorded, not dropped");

    let fixture = Fixture::new();
    let run = fixture.run(
        vec![
            RunEvent::ExecConfirmed,
            evidence_lost(),
            evidence_lost(),
            RunEvent::WallExpired,
        ],
        &[
            "--profile",
            "none",
            "--evidence",
            "strict",
            "--limit",
            "wall=1h",
        ],
    );
    assert_eq!(run.stops.first(), Some(&StopReason::EvidenceLoss));
    assert_eq!(
        run.receipt["outcome"]["cause"], "evidence_loss",
        "{:#}",
        run.receipt["outcome"]
    );
    let wall = run.receipt["applied"]["limits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|limit| limit["key"] == "wall")
        .cloned()
        .unwrap();
    assert_eq!(wall["hit"], true, "the later deadline is its limit's hit");

    let fixture = Fixture::new();
    let run = fixture.run(
        vec![
            RunEvent::ExecConfirmed,
            evidence_lost(),
            RunEvent::WallExpired,
        ],
        &[
            "--profile",
            "none",
            "--evidence",
            "best-effort",
            "--limit",
            "wall=1h",
        ],
    );
    assert_eq!(run.stops, vec![StopReason::WallExpiry]);
    assert_eq!(
        run.receipt["outcome"]["cause"], "wall_expiry",
        "under best-effort the loss was never a stop: {:#}",
        run.receipt["outcome"]
    );
}

/// Loss never changes a protection label. Every receipt revision of the
/// attempt — prepared, enforced after exec, settled after the loss — carries
/// the profile's containment and protection, in both evidence modes.
#[test]
fn j4_r04_protection_labels_never_change() {
    for (profile, containment, protection) in [
        ("none", "none", "unprotected"),
        ("tool", "enforced", "enforced"),
    ] {
        for evidence in ["strict", "best-effort"] {
            let fixture = Fixture::new();
            let run = fixture.run(
                vec![
                    RunEvent::ExecConfirmed,
                    RunEvent::Poll,
                    evidence_lost(),
                    RunEvent::Poll,
                    evidence_lost(),
                ],
                &["--profile", profile, "--evidence", evidence],
            );
            let phases: Vec<&str> = run
                .labels
                .iter()
                .map(|(phase, _, _)| phase.as_str())
                .collect();
            assert_eq!(
                phases,
                ["prepared", "enforced", "settled"],
                "{profile}/{evidence}: every revision was read: {:?}",
                run.labels
            );
            for (phase, seen_containment, seen_protection) in &run.labels {
                assert_eq!(
                    (seen_containment.as_str(), seen_protection.as_str()),
                    (containment, protection),
                    "{profile}/{evidence}: the {phase} receipt changed a label"
                );
            }
            assert_coverage_is_honest(&run.receipt);
        }
    }
}
