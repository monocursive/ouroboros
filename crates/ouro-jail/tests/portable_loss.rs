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
//! - J4 wave 2, R-1: a loss the platform never reported as an event (queued
//!   during settlement, or found when the observer stopped) is still an
//!   `evidence_lost` error and exit 1: any evidence class degraded at
//!   settlement is, whatever the loss's timing.
//! - J4 wave 2, R-2: a loss after the target's own end is recorded (errors,
//!   exit 1) but is not a stop and never replaces the natural end as
//!   `outcome.cause`.
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
    /// The contained boundary applied the outside proxy (`agent`'s network
    /// mode), so `proxy.net` is a class of its own.
    proxy: bool,
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
                mode: if self.0.proxy { "proxy" } else { "none" }.into(),
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
        after_target_end: false,
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
        self.run_covered(events, flags, degraded_coverage())
    }

    /// [`Fixture::run`] with the observer's final account given.
    fn run_covered(
        &self,
        events: Vec<RunEvent>,
        flags: &[&str],
        coverage: CoverageSummary,
    ) -> Outcome {
        let proxy = coverage
            .classes
            .get(&CoverageClass::ProxyNet)
            .is_some_and(|class| class.status != SourceStatus::Unsupported);
        let script = Script {
            events,
            data: self.data.clone(),
            coverage,
            stops: Arc::default(),
            labels: Arc::default(),
            contained: flags.contains(&"tool"),
            proxy,
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

// ---------------------------------------------------------------------------
// J4 wave 2, R-1: a loss found at settlement is reported, whatever its timing
// ---------------------------------------------------------------------------

/// The account of an observer that saw everything: every audit class active
/// with its exact count.
fn clean_coverage() -> CoverageSummary {
    let mut summary = degraded_coverage();
    let active = |count| ClassSummary {
        status: SourceStatus::Active,
        observed_count: Some(count),
        gaps: Vec::new(),
    };
    summary.sources.audit = SourceStatus::Active;
    summary.gaps.clear();
    summary.classes.insert(CoverageClass::FsWrite, active(2));
    summary.classes.insert(CoverageClass::FsDeny, active(0));
    summary
}

fn evidence_lost_count(receipt: &Value) -> usize {
    error_codes(receipt)
        .iter()
        .filter(|code| *code == "evidence_lost")
        .count()
}

/// R-1 (slice L measured it live: `j4_r04_a_call_in_flight_at_teardown_is_loss`
/// exited 0 with `errors: []` under strict evidence). The platform queued no
/// loss event before the target's end — the loss was found while the tree was
/// torn down — yet the observer's account at settlement degrades `fs.write`
/// and `fs.deny`. Any evidence class degraded at settlement is an
/// `evidence_lost` error and exit 1, in both modes and both profiles. Nothing
/// stopped the target, so there is no stop and no cause: its own end stays
/// the outcome.
#[test]
fn j4_w2s_r1_a_loss_found_at_settlement_is_an_error_and_exit_1() {
    for profile in ["none", "tool"] {
        for evidence in ["strict", "best-effort"] {
            let label = format!("{profile}/{evidence}");
            let fixture = Fixture::new();
            let run = fixture.run(
                vec![RunEvent::ExecConfirmed, RunEvent::TargetExited { code: 0 }],
                &["--profile", profile, "--evidence", evidence],
            );
            assert_coverage_is_honest(&run.receipt);
            assert_eq!(
                evidence_lost_count(&run.receipt),
                1,
                "{label}: the loss is one evidence_lost error: {:#}",
                run.receipt["errors"]
            );
            assert_eq!(
                run.report.exit_code, 1,
                "{label}: a degraded class at settlement exits 1"
            );
            assert_eq!(
                run.report.error.as_ref().map(|error| error.code),
                Some(ErrorCode::EvidenceLost),
                "{label}"
            );
            let outcome = &run.receipt["outcome"];
            assert_eq!(outcome["kind"], "exited", "{label}: {outcome:#}");
            assert_eq!(outcome["code"], 0, "{label}: {outcome:#}");
            assert_eq!(
                outcome["cause"],
                Value::Null,
                "{label}: the target ended by itself: {outcome:#}"
            );
            assert!(run.stops.is_empty(), "{label}: {:?}", run.stops);
        }
    }
}

/// R-1, the other side: a loss the platform did report during the run is
/// the one error; finding the same degraded classes at settlement adds no
/// second one.
#[test]
fn j4_w2s_r1_a_reported_loss_is_not_reported_twice_at_settlement() {
    for evidence in ["strict", "best-effort"] {
        let fixture = Fixture::new();
        let run = fixture.run(
            vec![RunEvent::ExecConfirmed, RunEvent::Poll, evidence_lost()],
            &["--profile", "tool", "--evidence", evidence],
        );
        assert_eq!(
            evidence_lost_count(&run.receipt),
            1,
            "{evidence}: {:#}",
            run.receipt["errors"]
        );
        assert_eq!(run.report.exit_code, 1, "{evidence}");
    }
}

/// R-1 covers the proxy's class too: §11.4 handles a lost `proxy.net`
/// result as evidence loss (strict stops for it in the run loop), so a
/// `proxy.net` degraded only at settlement — the proxy's last results not
/// drained — is the same `evidence_lost` error and exit 1.
#[test]
fn j4_w2s_r1_a_proxy_loss_found_at_settlement_is_an_error() {
    let mut coverage = clean_coverage();
    coverage.sources.proxy = SourceStatus::Degraded;
    coverage.classes.insert(
        CoverageClass::ProxyNet,
        ClassSummary {
            status: SourceStatus::Degraded,
            observed_count: None,
            gaps: vec![Gap {
                classes: vec!["proxy.net".into()],
                source: "proxy".into(),
                start_ns: "0".into(),
                end_ns: Some("2000".into()),
                reason: "proxy_drain_incomplete".into(),
                lost_count: Some(1),
            }],
        },
    );
    let fixture = Fixture::new();
    let run = fixture.run_covered(
        vec![RunEvent::ExecConfirmed, RunEvent::TargetExited { code: 0 }],
        &["--profile", "tool", "--evidence", "strict"],
        coverage,
    );
    assert_eq!(
        evidence_lost_count(&run.receipt),
        1,
        "{:#}",
        run.receipt["errors"]
    );
    assert!(
        run.receipt["errors"][0]["message"]
            .as_str()
            .is_some_and(|message| message.contains("proxy.net")),
        "{:#}",
        run.receipt["errors"]
    );
    assert_eq!(run.report.exit_code, 1);
    assert_eq!(run.receipt["outcome"]["cause"], Value::Null);
}

/// R-1 never invents a loss: every class active at settlement, no error, and
/// the jail exits with the target's own code.
#[test]
fn j4_w2s_r1_full_coverage_at_settlement_is_no_error() {
    for profile in ["none", "tool"] {
        let fixture = Fixture::new();
        let run = fixture.run_covered(
            vec![RunEvent::ExecConfirmed, RunEvent::TargetExited { code: 0 }],
            &["--profile", profile, "--evidence", "strict"],
            clean_coverage(),
        );
        assert_eq!(
            run.receipt["errors"],
            serde_json::json!([]),
            "{profile}: {:#}",
            run.receipt
        );
        assert_eq!(run.report.exit_code, 0, "{profile}: {:?}", run.report.error);
        assert_eq!(run.receipt["coverage"]["fs.write"]["status"], "active");
    }
}

// ---------------------------------------------------------------------------
// J4 wave 2, R-2: a loss after the target's own end is not the cause
// ---------------------------------------------------------------------------

/// A loss the platform processed after it had seen the target's own end.
fn evidence_lost_after_end() -> RunEvent {
    RunEvent::EvidenceLost {
        reason: "the closed-set observer lost coverage: entry_abandoned".into(),
        after_target_end: true,
    }
}

/// R-2. The contained platform learns the target's exit from the observer
/// and reports it only once the backend has ended too, so a call abandoned
/// by the namespace's teardown reaches the supervisor as a loss event before
/// the exit event, although it happened after it. Under strict evidence that
/// loss used to become `outcome.cause: evidence_loss` beside `exited 0`. A
/// loss after the target's end is recorded (one `evidence_lost`, exit 1) but
/// asks for no stop and does not replace the natural end: the cause stays
/// null, in both modes.
#[test]
fn j4_w2s_r2_a_loss_after_the_target_ended_is_recorded_not_the_cause() {
    for evidence in ["strict", "best-effort"] {
        for profile in ["tool", "none"] {
            let label = format!("{profile}/{evidence}");
            let fixture = Fixture::new();
            let run = fixture.run(
                vec![
                    RunEvent::ExecConfirmed,
                    evidence_lost_after_end(),
                    RunEvent::TargetExited { code: 0 },
                ],
                &["--profile", profile, "--evidence", evidence],
            );
            let outcome = &run.receipt["outcome"];
            assert_eq!(
                outcome["cause"],
                Value::Null,
                "{label}: the target's own end is the outcome: {outcome:#}"
            );
            assert_eq!(outcome["kind"], "exited", "{label}: {outcome:#}");
            assert_eq!(outcome["code"], 0, "{label}: {outcome:#}");
            assert!(
                run.stops.is_empty(),
                "{label}: nothing is left to stop: {:?}",
                run.stops
            );
            assert_eq!(
                evidence_lost_count(&run.receipt),
                1,
                "{label}: {:#}",
                run.receipt["errors"]
            );
            assert_eq!(run.report.exit_code, 1, "{label}");
            assert_eq!(
                run.report.error.as_ref().map(|error| error.code),
                Some(ErrorCode::EvidenceLost),
                "{label}"
            );
            assert_coverage_is_honest(&run.receipt);
        }
    }
}
