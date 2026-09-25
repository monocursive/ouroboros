//! J4 wave 2, slice W2-S: the receipts and the trace after a trace loss
//! (jail-v1 §§13.2, 13.3), found by the adversarial review of slice T.
//!
//! - (A) §13.3: "A trace is complete only if its last frame is the
//!   `jail.receipt` note of the attempt's final receipt", and the reserve
//!   exists for the final notes. The note of the final receipt is reserve
//!   priority whatever its phase: an attempt that ends unsettled keeps its
//!   last nonsettled phase (`enforced`, `prepared`), and its final note used
//!   to be refused after a loss although the reserve had room.
//! - (B) Once a trace loss is known, every receipt written afterwards carries
//!   the degraded wrapper source and its `trace_transport_loss` gap: the
//!   `enforced` receipt written while the target runs, and the `refused`
//!   receipt of an exec error, used to read wrapper `supported` with no gap
//!   when the run loop had already taken the loss.
//!
//! The platform is simulated and the filesystem is real. The trace loss is
//! real too: the simulated platform writes filler events into the shared
//! trace until the payload budget, shrunk by the S9 seam
//! `OURO_JAIL_TEST_TRACE_CAP`, refuses one. Every test here runs under one
//! lock, and the seam is set once, under it, before any run reads it.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use clap::Parser as _;
use ouro_jail::capability::{Capability, CapabilityScope, CapabilityStatus};
use ouro_jail::config::EnvSettings;
use ouro_jail::platform::{
    BoundaryIdentity, Deadline, OwnerIdentity, PlanRequest, Platform, PlatformIdentity,
    PreparedExecution, PreparedPlan, RunEvent, RunningExecution, Sinks, StopReason, Teardown,
    TreeObservation,
};
use ouro_jail::records::{
    Event, JailError, NativeLifetime, Os, ProcessIdentity, ProcessRecord, rfc3339_utc,
};
use ouro_jail::trace::{Priority, SharedTrace, TRACE_CAP_SEAM, TRANSPORT_LOSS_REASON};
use ouro_jail::{cli, supervisor};
use serde_json::Value;

mod common;

/// The shrunk local trace cap every run here uses.
const CAP: &str = "65536";

/// Serialises the runs, and sets the seam once before the first of them.
fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    static SET: std::sync::Once = std::sync::Once::new();
    let guard = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    SET.call_once(|| {
        // SAFETY: every test of this binary takes `SERIAL` before it reads
        // the environment (only `supervisor::run` does), so nothing reads
        // it while it is written.
        unsafe { std::env::set_var(TRACE_CAP_SEAM, CAP) };
    });
    guard
}

/// What the simulated target does, one step per `wait`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    /// Exhaust the trace payload, then report a poll.
    Fill,
    Poll,
    /// A poll after a pause long enough for the persistence worker to land
    /// what it holds, so the loop acknowledges it before the target ends.
    Pause,
    Exec,
    ExecError,
    Signaled,
    Exited,
}

#[derive(Clone)]
struct Script {
    steps: Vec<Step>,
    /// The integrity tree verification ends with: `verified` settles,
    /// `lost` leaves the attempt unsettled.
    integrity: &'static str,
    data: PathBuf,
    /// `jail.json` as it was on disk when the observer's final account was
    /// read (after the tree's end and the receipts still in flight, before
    /// any settlement write): the last receipt written while the target ran.
    before_settlement: Arc<Mutex<Option<Value>>>,
    // J4 W3 begin: P4
    /// The observer's final account is an attached audit observer whose
    /// frames the lost sink refused, as the Linux audit writer reports it:
    /// `fs.write` degraded with a null count (instead of observation off).
    observed: bool,
    /// The trace payload is exhausted while the tree is verified, after the
    /// run loop's last iteration, as a tracer draining at settlement does.
    fill_at_settlement: bool,
    // J4 W3 end
}

struct Simulated(Script);
struct Prepared(Script, Option<SharedTrace>);
struct Running {
    script: Script,
    step: usize,
    trace: Option<SharedTrace>,
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
                evidence_ref: Some("trace-loss simulation".into()),
            })
            .collect()
    }
    fn prepare(
        &self,
        _: PreparedPlan,
        sinks: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        Ok(Box::new(Prepared(self.0.clone(), sinks.trace)))
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
            trace: self.1,
        }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown { tree: None })
    }
}

/// Writes filler into the shared trace until the sink refuses one: a real
/// payload exhaustion, which the sink records as its loss.
fn exhaust(trace: &SharedTrace) {
    let filler = "f".repeat(400);
    for index in 0..10_000 {
        let event = Event::lifecycle_note(
            "att_simulated",
            0,
            SystemTime::now(),
            0,
            &format!("filler_{index}_{filler}"),
        );
        if trace
            .lock()
            .unwrap()
            .write_event(&event, Priority::Normal)
            .is_err()
        {
            return;
        }
    }
    panic!("the trace payload was never exhausted");
}

impl RunningExecution for Running {
    fn wait(&mut self, _: Deadline) -> RunEvent {
        let step = self.script.steps.get(self.step).copied();
        self.step += 1;
        match step {
            Some(Step::Fill) => {
                exhaust(self.trace.as_ref().expect("a trace sink"));
                RunEvent::Poll
            }
            Some(Step::Poll) => RunEvent::Poll,
            Some(Step::Pause) => {
                std::thread::sleep(Duration::from_millis(300));
                RunEvent::Poll
            }
            Some(Step::Exec) => RunEvent::ExecConfirmed,
            Some(Step::ExecError) => RunEvent::ExecError {
                errno: "ENOENT".into(),
                detail: None,
            },
            Some(Step::Signaled) => RunEvent::TargetSignaled { signal: 9 },
            Some(Step::Exited) | None => RunEvent::TargetExited { code: 0 },
        }
    }
    fn request_stop(&mut self, _: StopReason) {}
    fn wait_tree(&mut self, _: Duration) -> TreeObservation {
        if self.script.fill_at_settlement {
            exhaust(self.trace.as_ref().expect("a trace sink"));
        }
        let settled = self.script.integrity == "verified";
        TreeObservation {
            tree_empty: settled.then_some(true),
            verified_at: settled.then(SystemTime::now),
            verification_scope: "registered_boundary".into(),
            integrity: self.script.integrity.into(),
        }
    }
    fn observer_summary(&mut self) -> Option<ouro_jail::observer::CoverageSummary> {
        // J4 W3: taken here, not when tree verification begins: since P3 the
        // tree is ended before the receipts still with the persistence worker
        // are waited for, and the observer's account is read after them.
        let receipt = std::fs::read_dir(self.script.data.join("attempts"))
            .ok()
            .and_then(|mut listing| listing.next())
            .and_then(|entry| std::fs::read(entry.ok()?.path().join("jail.json")).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        *self.script.before_settlement.lock().unwrap() = receipt;
        if self.script.observed {
            return Some(observed_summary());
        }
        // Observation off: the audit classes unsupported, the wrapper's own
        // `limits` class active with no hit (what the Linux platforms report).
        let mut summary = ouro_jail::observer::CoverageSummary::unobserved();
        summary.classes.insert(
            ouro_jail::observer::CoverageClass::Limits,
            ouro_jail::observer::ClassSummary {
                status: ouro_jail::records::SourceStatus::Active,
                observed_count: Some(0),
                gaps: Vec::new(),
            },
        );
        Some(summary)
    }
}

/// One run: its final receipt, the receipt on disk when settlement began,
/// and its trace.
struct Outcome {
    receipt: Value,
    before_settlement: Option<Value>,
    trace: ouro_jail::trace::Readback,
}

/// An attached audit observer's final account after the lost sink refused
/// one `fs.write` frame: the class degraded with a null count and the audit
/// source degraded (`audit.rs`, `emit`), the rest active, `limits` active
/// with no hit.
fn observed_summary() -> ouro_jail::observer::CoverageSummary {
    use ouro_jail::observer::{ClassSummary, CoverageClass, CoverageSummary};
    use ouro_jail::records::{SourceHealth, SourceStatus};
    let active = |count| ClassSummary {
        status: SourceStatus::Active,
        observed_count: Some(count),
        gaps: Vec::new(),
    };
    CoverageSummary {
        backend: Some("ptrace".into()),
        set: Some(CoverageSummary::linux_closed_set().into()),
        attached: true,
        sources: SourceHealth {
            wrapper: SourceStatus::Active,
            audit: SourceStatus::Degraded,
            proxy: SourceStatus::Unsupported,
        },
        gaps: Vec::new(),
        classes: [
            (CoverageClass::Exec, active(1)),
            (
                CoverageClass::FsWrite,
                ClassSummary {
                    status: SourceStatus::Degraded,
                    observed_count: None,
                    gaps: Vec::new(),
                },
            ),
            (CoverageClass::FsDeny, active(0)),
            (CoverageClass::Net, active(0)),
            (CoverageClass::ProxyNet, ClassSummary::unsupported()),
            (CoverageClass::Limits, active(0)),
        ]
        .into_iter()
        .collect(),
    }
}

fn run(steps: &[Step], integrity: &'static str) -> Outcome {
    run_script(steps, integrity, false, false)
}

fn run_script(
    steps: &[Step],
    integrity: &'static str,
    observed: bool,
    fill_at_settlement: bool,
) -> Outcome {
    let dir = common::private_tempdir();
    let root = dir.path().canonicalize().unwrap();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let data = root.join("data");
    let script = Script {
        steps: steps.to_vec(),
        integrity,
        data: data.clone(),
        before_settlement: Arc::default(),
        observed,
        fill_at_settlement,
    };
    let before_settlement = Arc::clone(&script.before_settlement);
    let cli::Command::Run(args) = cli::Cli::parse_from([
        "ouro-jail",
        "run",
        "--profile",
        "none",
        "--evidence",
        "best-effort",
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
            config_dir: Some(root.join("config")),
            data_dir: Some(data.clone()),
            ..Default::default()
        },
        cwd: workspace,
        home: None,
        env_lookup: Box::new(|_| None),
    };
    let report = supervisor::run(&context, &args);
    let receipt = serde_json::to_value(
        report
            .receipt
            .unwrap_or_else(|| panic!("a receipt; the run ended with {:?}", report.error)),
    )
    .unwrap();
    common::check_receipt(&receipt).unwrap_or_else(|error| panic!("{error}\n{receipt:#}"));
    let attempt = std::fs::read_dir(data.join("attempts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let trace =
        ouro_jail::trace::read_frames(&std::fs::read(attempt.join("trace.ndjson")).unwrap());
    let before_settlement = before_settlement.lock().unwrap().clone();
    Outcome {
        receipt,
        before_settlement,
        trace,
    }
}

/// The digests a receipt note may name for `receipt`: over its serialized
/// bytes (this branch's base), or over its RFC 8785 canonical bytes (j4 from
/// 62d09d40 on). Either identifies this receipt and no other.
fn digests(receipt: &Value) -> [String; 2] {
    let typed: ouro_jail::records::Receipt = serde_json::from_value(receipt.clone()).unwrap();
    let canonical = ouro_jail::canonical::to_jcs(&serde_json::to_value(&typed).unwrap()).unwrap();
    [
        ouro_jail::canonical::sha256_prefixed(&serde_json::to_vec(&typed).unwrap()),
        ouro_jail::canonical::sha256_prefixed(&canonical),
    ]
}

/// The receipt says what the trace loss took: the wrapper source degraded,
/// and every evidence class the receipt covers at all (not `unsupported`)
/// degraded with a null count and a `trace_transport_loss` gap. Returns how
/// many classes that was.
///
/// J4 W3: `limits` is not one of them. Its count comes from the cgroup
/// counters, not from the trace (§11.4: no `limit.hit` event in v1), so a
/// trace loss leaves it as the platform reported it.
fn assert_trace_loss_recorded(label: &str, receipt: &Value) -> usize {
    assert_eq!(
        receipt["observer"]["sources"]["wrapper"], "degraded",
        "{label}: {:#}",
        receipt["observer"]
    );
    let limits = &receipt["coverage"]["limits"];
    assert!(
        limits["status"] != "degraded"
            && !limits["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|gap| gap["reason"] == TRANSPORT_LOSS_REASON),
        "{label}: a trace loss degraded `limits`, whose count is not trace-derived: {limits:#}"
    );
    assert!(
        !receipt["observer"]["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap["reason"] == TRANSPORT_LOSS_REASON
                && gap["classes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|class| class == "limits")),
        "{label}: an observer gap names `limits`: {:#}",
        receipt["observer"]["gaps"]
    );
    let mut covered = 0;
    for (class, entry) in receipt["coverage"].as_object().unwrap() {
        if entry["status"] == "unsupported" || class == "limits" {
            continue;
        }
        covered += 1;
        assert_eq!(entry["status"], "degraded", "{label}: {class}: {entry:#}");
        assert!(entry["observed_count"].is_null(), "{label}: {class}");
        let gaps = entry["gaps"].as_array().unwrap();
        assert_eq!(
            gaps.iter()
                .filter(|gap| gap["reason"] == TRANSPORT_LOSS_REASON)
                .count(),
            1,
            "{label}: {class}: one {TRANSPORT_LOSS_REASON} gap: {entry:#}"
        );
    }
    covered
}

// ---------------------------------------------------------------------------
// (A) the final receipt note gets the reserve, whatever its phase
// ---------------------------------------------------------------------------

/// (A). After the payload is exhausted, a settled attempt's trace ends on
/// the note of its final receipt, and so must an attempt that ends
/// unsettled (integrity lost, so `enforced` stays its phase): the reserve
/// is there for exactly that note.
#[test]
fn j4_w2s_a_an_unsettled_attempts_final_receipt_note_uses_the_reserve() {
    let _serial = serial();
    for (integrity, phase) in [("verified", "settled"), ("lost", "enforced")] {
        let outcome = run(&[Step::Exec, Step::Fill, Step::Signaled], integrity);
        assert_eq!(outcome.receipt["phase"], phase, "{integrity}");
        assert!(
            outcome.receipt["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|error| error["code"] == "evidence_lost"),
            "{integrity}: the payload was exhausted: {:#}",
            outcome.receipt["errors"]
        );
        let notes: Vec<&Value> = outcome
            .trace
            .frames
            .iter()
            .filter(|frame| frame["operation"] == "jail.receipt")
            .map(|frame| &frame["fields"]["phase"])
            .collect();
        let note = outcome.trace.last_receipt_note();
        assert!(
            note.is_some_and(|(noted, digest)| noted == phase
                && digests(&outcome.receipt)
                    .iter()
                    .any(|known| known == digest)),
            "{integrity}: the trace must end on the final {phase} receipt's note, not on its \
             last frame {:#} ({:?}); receipt notes: {notes:?}",
            outcome.trace.frames.last().unwrap(),
            outcome.trace.state
        );
    }
}

// ---------------------------------------------------------------------------
// (B) every receipt after a known trace loss says so
// ---------------------------------------------------------------------------

/// (B), the refusal. The run loop takes the trace loss, then the target's
/// exec fails: the `refused` receipt lists the loss and carries the
/// degraded wrapper source and its gap, as a refusal before the loop does.
#[test]
fn j4_w2s_b_a_refusal_after_a_taken_trace_loss_records_it_in_coverage() {
    let _serial = serial();
    let outcome = run(&[Step::Fill, Step::Poll, Step::ExecError], "verified");
    assert_eq!(outcome.receipt["phase"], "refused");
    assert_eq!(outcome.receipt["outcome"]["kind"], "exec_error");
    assert!(
        outcome.receipt["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error["code"] == "evidence_lost"),
        "{:#}",
        outcome.receipt["errors"]
    );
    // A refusal covers nothing, so the wrapper source is what says it.
    assert_trace_loss_recorded("refused", &outcome.receipt);
}

/// (B), while the target runs. The loss is known before the target's exec
/// is confirmed, so the `enforced` receipt written while it runs carries the
/// degraded wrapper source and the gap; the settled receipt does too.
#[test]
fn j4_w2s_b_the_enforced_receipt_after_a_trace_loss_records_it_in_coverage() {
    let _serial = serial();
    let outcome = run(
        &[Step::Fill, Step::Poll, Step::Exec, Step::Exited],
        "verified",
    );
    let enforced = outcome
        .before_settlement
        .expect("the enforced receipt was on disk");
    assert_eq!(enforced["phase"], "enforced");
    common::check_receipt(&enforced).unwrap_or_else(|error| panic!("{error}\n{enforced:#}"));
    assert_trace_loss_recorded("enforced", &enforced);
    assert_eq!(outcome.receipt["phase"], "settled");
    assert_eq!(
        assert_trace_loss_recorded("settled", &outcome.receipt),
        0,
        "`limits` is the one class a run with observation off covers, and a trace loss \
         leaves it alone"
    );
    assert_eq!(
        outcome.receipt["coverage"]["limits"]["status"], "active",
        "{:#}",
        outcome.receipt["coverage"]["limits"]
    );
    assert_eq!(outcome.receipt["coverage"]["limits"]["observed_count"], 0);
}

// ---------------------------------------------------------------------------
// J4 W3: P4, and `limits` after a trace loss
// ---------------------------------------------------------------------------

fn evidence_lost(receipt: &Value) -> Vec<String> {
    receipt["errors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|error| error["code"] == "evidence_lost")
        .map(|error| error["message"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// P4. A trace-sink loss the journal already reported also degrades the
/// audit classes whose frames the lost sink refused; the settlement check
/// (R-1) saw only whether the platform had reported a loss and reported the
/// same loss again ("coverage was lost by settlement ... the loss reached no
/// run event"): two `evidence_lost` errors for one loss (3 of 3 live). A
/// journal loss counts as reported, whether the loop took it or it happened
/// while the tree was verified.
#[test]
fn j4_w3_p4_a_trace_loss_is_reported_once() {
    let _serial = serial();
    let mut problems = Vec::new();
    for (label, steps, at_settlement) in [
        (
            "the loop took the loss",
            &[Step::Exec, Step::Fill, Step::Poll, Step::Exited][..],
            false,
        ),
        (
            // The enforced receipt is acknowledged in the loop, so nothing
            // the supervisor writes between the tree's end and the check
            // below notices the loss for it.
            "the loss came while the tree was verified",
            &[Step::Exec, Step::Pause, Step::Poll, Step::Exited][..],
            true,
        ),
    ] {
        let outcome = run_script(steps, "verified", true, at_settlement);
        let errors = evidence_lost(&outcome.receipt);
        if errors.len() != 1 || errors[0].contains("coverage was lost by settlement") {
            problems.push(format!(
                "{label}: one loss must be one evidence_lost error naming the trace loss: \
                 {errors:#?}"
            ));
        }
        assert_eq!(
            outcome.receipt["coverage"]["fs.write"]["status"], "degraded",
            "{label}"
        );
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// J4 W3 decision: after a trace transport loss, `limits` keeps what the
/// platform reported. Its count comes from the cgroup counters (§11.4: no
/// `limit.hit` event in v1), so no frame of it can have been lost; the audit
/// classes are degraded as before.
#[test]
fn j4_w3_a_trace_loss_leaves_the_limits_class_alone() {
    let _serial = serial();
    let outcome = run_script(
        &[Step::Exec, Step::Fill, Step::Poll, Step::Exited],
        "verified",
        true,
        false,
    );
    assert_eq!(outcome.receipt["phase"], "settled");
    assert_eq!(
        assert_trace_loss_recorded("settled", &outcome.receipt),
        4,
        "the four audit classes"
    );
    let limits = &outcome.receipt["coverage"]["limits"];
    assert_eq!(limits["status"], "active", "{limits:#}");
    assert_eq!(limits["observed_count"], 0, "{limits:#}");
    assert_eq!(limits["sources"], serde_json::json!(["wrapper"]));
}
