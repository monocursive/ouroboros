//! `cargo xtask perf`: the performance measurement of jail-v1 §5.
//!
//! The spec asks for "at least 30 launches each for a no-op command, a
//! descendant-heavy fixture and a fixed file-operation workload, with
//! observation on/off", reporting "median/p95 startup, wall time, peak RSS,
//! event counts and losses on the named host", against two initial budgets:
//! under 250 ms p95 added warm startup and under 20% median overhead on the
//! fixed workload. The user decided on 2026-09-24 that, if observation misses
//! them, the budgets apply to the jail's own overhead (`--observe off` against
//! direct execution) and observation cost is reported per workload. The
//! summary therefore states both comparisons for every workload and profile.
//!
//! `run` executes on the reference host, from a plain lingering login session:
//! it takes the plain-session pass itself and re-executes itself under
//! `systemd-run --user --scope` for the pre-entered-scope pass. Every launch
//! goes through `ouro-fixture perf-launch`, which reads `CLOCK_MONOTONIC`
//! just before `fork`, samples the launched process's `VmHWM` and the
//! execution leaf's `memory.peak`, reaps with `wait4` and harvests the
//! attempt directory (trace counts and the §13.3 completeness check). The
//! workloads print their own readings of the same clock. This module turns
//! those facts into one raw record per launch (`launches.ndjson`), decides
//! validity, and summarises (`summary.json`, `summary.md`). `summarize`
//! recomputes the summary from the raw records alone.
//!
//! Nothing here averages an invalid launch: a launch is excluded with its
//! reasons and counted per arm. A budget verdict needs at least 30 valid
//! launches on both sides; below that it says `insufficient`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// jail-v1 §5: "at least 30 launches each".
pub const SPEC_MIN_LAUNCHES: usize = 30;
/// jail-v1 §5: "under 250 ms p95 added warm startup".
pub const STARTUP_BUDGET_MS: f64 = 250.0;
/// jail-v1 §5: "under 20% median overhead on the fixed workload".
pub const OVERHEAD_BUDGET_PCT: f64 = 20.0;

const RECORD_SCHEMA: &str = "xtask.perf.launch/1";
const SUMMARY_SCHEMA: &str = "xtask.perf.summary/1";
const RAW_FILE: &str = "launches.ndjson";
const PARAMETERS_FILE: &str = "parameters.json";
const HOST_FILE: &str = "host.json";
const PASSES_FILE: &str = "passes.ndjson";

/// The cause the supervisor records when, with observation off, the target
/// ended before the backend's exec could be confirmed independently
/// (`platform/linux/platform.rs`, `terminal_event`).
pub const EXEC_UNCONFIRMED: &str = "the backend ended without independent evidence of target exec";

/// The closed-set classes an attached observer must report active.
const CLOSED_SET: [&str; 4] = ["exec", "fs.write", "fs.deny", "net"];

// ----------------------------------------------------------------------- CLI

#[derive(Args, Debug)]
pub struct Cli {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Measure on this host (Linux, the reference host, as the operator).
    Run(Box<RunArgs>),
    /// Recompute `summary.json` and `summary.md` from a run directory.
    Summarize {
        /// The run directory holding `launches.ndjson`.
        #[arg(long, value_name = "DIR")]
        dir: PathBuf,
    },
}

#[derive(Args, Debug, Clone, PartialEq)]
pub struct RunArgs {
    /// Measured launches per arm, after the warm-up.
    #[arg(long, default_value_t = 30)]
    pub launches: u32,
    /// Discarded warm-up launches per arm.
    #[arg(long, default_value_t = 1)]
    pub warmup: u32,
    #[arg(long, value_enum, value_delimiter = ',', default_values_t = [Session::Plain, Session::Scope])]
    pub sessions: Vec<Session>,
    /// `tool` is the budget profile; `agent` and `none` are informational.
    #[arg(long, value_enum, value_delimiter = ',', default_values_t = [Profile::Tool, Profile::Agent, Profile::None])]
    pub profiles: Vec<Profile>,
    #[arg(long, value_enum, value_delimiter = ',', default_values_t = [Workload::Noop, Workload::SpawnTree, Workload::Fileops])]
    pub workloads: Vec<Workload>,
    /// Rounds of create, rename and unlink (J0: 5,000).
    #[arg(long, default_value_t = 5000)]
    pub fileops_rounds: u32,
    /// Children forked and exec'd one at a time (J0: 200).
    #[arg(long, default_value_t = 200)]
    pub spawn_count: u32,
    /// `perf-launch` sampling interval; 0 disables RSS sampling.
    #[arg(long, default_value_t = 5)]
    pub sample_ms: u64,
    /// Per-launch deadline before `perf-launch` sends SIGTERM.
    #[arg(long, default_value_t = 300_000)]
    pub deadline_ms: u64,
    /// Refuse to start a pass while the 1-minute load average is above this.
    #[arg(long, value_name = "LOAD")]
    pub max_load: Option<f64>,
    /// `ouro-jail`; default `target/release/ouro-jail`.
    #[arg(long, value_name = "PATH")]
    pub jail: Option<PathBuf>,
    /// `ouro-fixture`; default `target/release/ouro-fixture`.
    #[arg(long, value_name = "PATH")]
    pub fixture: Option<PathBuf>,
    /// Output directory; default `evidence/perf-<UTC stamp>`.
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
    /// The source revision the binaries were built from, for the record.
    #[arg(long, value_name = "SHA")]
    pub revision: Option<String>,
    /// Internal: this process is the scope pass of the run in DIR.
    #[arg(long, value_name = "DIR", hide = true)]
    pub inner: Option<PathBuf>,
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum Session {
    /// A plain login session: the supervisor takes the revision-18 scope step.
    Plain,
    /// A pre-entered delegated user scope (`systemd-run --user --scope`).
    Scope,
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum Workload {
    /// `ouro-fixture spawn-tree 0`: start, report, exit.
    Noop,
    /// `ouro-fixture spawn-tree N -- /usr/bin/true`.
    SpawnTree,
    /// `ouro-fixture fileops N DIR`.
    Fileops,
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ValueEnum,
)]
pub enum Profile {
    #[serde(rename = "tool")]
    Tool,
    #[serde(rename = "agent")]
    Agent,
    #[serde(rename = "none")]
    None,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Observe {
    Off,
    On,
}

impl Session {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Session::Plain => "plain",
            Session::Scope => "scope",
        }
    }

    /// The `supervisor_scope.state` a launch from this session must record.
    #[must_use]
    pub fn expected_scope_state(self) -> &'static str {
        match self {
            Session::Plain => "entered",
            Session::Scope => "already_delegated",
        }
    }
}

impl Workload {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Workload::Noop => "noop",
            Workload::SpawnTree => "spawn-tree",
            Workload::Fileops => "fileops",
        }
    }

    /// The `op` of the workload's summary line.
    #[must_use]
    pub fn end_op(self) -> &'static str {
        match self {
            Workload::Noop | Workload::SpawnTree => "spawn-tree",
            Workload::Fileops => "fileops",
        }
    }
}

impl Profile {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Profile::Tool => "tool",
            Profile::Agent => "agent",
            Profile::None => "none",
        }
    }
}

impl Observe {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Observe::Off => "off",
            Observe::On => "on",
        }
    }
}

/// Direct execution, or one profile with one observation mode.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum Arm {
    Direct,
    Jailed(Profile, Observe),
}

impl Arm {
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Arm::Direct => "direct".to_owned(),
            Arm::Jailed(p, o) => format!("{}/{}", p.name(), o.name()),
        }
    }

    fn dir_name(self) -> String {
        self.name().replace('/', "-")
    }
}

impl From<Arm> for String {
    fn from(arm: Arm) -> String {
        arm.name()
    }
}

impl TryFrom<String> for Arm {
    type Error = String;
    fn try_from(s: String) -> Result<Arm, String> {
        if s == "direct" {
            return Ok(Arm::Direct);
        }
        let (p, o) = s
            .split_once('/')
            .ok_or_else(|| format!("`{s}` is not an arm"))?;
        let profile = match p {
            "tool" => Profile::Tool,
            "agent" => Profile::Agent,
            "none" => Profile::None,
            _ => return Err(format!("`{p}` is not a measured profile")),
        };
        let observe = match o {
            "off" => Observe::Off,
            "on" => Observe::On,
            _ => return Err(format!("`{o}` is not an observation mode")),
        };
        Ok(Arm::Jailed(profile, observe))
    }
}

/// The arms of one workload: direct first, then each profile off and on.
#[must_use]
pub fn arms(profiles: &[Profile]) -> Vec<Arm> {
    let mut out = vec![Arm::Direct];
    for p in profiles {
        out.push(Arm::Jailed(*p, Observe::Off));
        out.push(Arm::Jailed(*p, Observe::On));
    }
    out
}

/// The arm order of round `round`: rotated by one per round, so no arm
/// always runs right after another and slow drift in the host's load falls
/// on every arm alike.
#[must_use]
pub fn round_order(arms: &[Arm], round: u32) -> Vec<Arm> {
    if arms.is_empty() {
        return Vec::new();
    }
    let shift = round as usize % arms.len();
    arms.iter()
        .cycle()
        .skip(shift)
        .take(arms.len())
        .copied()
        .collect()
}

// ------------------------------------------------------------------- records

/// What `ouro-fixture perf-launch` wrote for one launch.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct LauncherFacts {
    pub pid: i64,
    pub t0_ns: u64,
    /// The launcher's reading once its child's exec is confirmed.
    pub exec_ns: u64,
    pub t1_ns: u64,
    pub timens: Option<String>,
    pub exec_errno: Option<String>,
    pub timed_out: bool,
    pub wait_errno: Option<String>,
    pub status: ExitFacts,
    pub rusage: RusageFacts,
    pub sampling: SamplingFacts,
    pub attempts: Option<Vec<AttemptFacts>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct ExitFacts {
    pub exited: bool,
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct RusageFacts {
    /// `wait4`'s `ru_maxrss`: the largest resident set of the launched
    /// process and every descendant it (transitively) reaped.
    pub maxrss_kib: u64,
    pub utime_us: u64,
    pub stime_us: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct SamplingFacts {
    pub interval_ms: u64,
    pub samples: u64,
    /// The launched process's own `VmHWM`, last sample (a lower bound).
    pub hwm_kib: Option<u64>,
    pub leaf_path: Option<String>,
    /// The execution leaf's `memory.peak`, last sample (a lower bound).
    pub leaf_peak_bytes: Option<u64>,
    pub leaf_samples: u64,
    pub leaf_note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct AttemptFacts {
    pub id: Option<String>,
    pub dir: String,
    pub receipt: bool,
    pub trace: TraceFacts,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct TraceFacts {
    pub bytes: u64,
    pub state: String,
    pub frames: u64,
    /// Why the trace is not a complete transcript ending on the note of the
    /// final receipt (§13.3), or null when it is one.
    pub guard: Option<String>,
    pub by_source: BTreeMap<String, u64>,
    pub by_operation: BTreeMap<String, u64>,
    pub notes: BTreeMap<String, u64>,
    pub error: Option<String>,
}

/// The target's own two lines.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct TargetFacts {
    pub lines: usize,
    pub start_ns: Option<u64>,
    pub timens: Option<String>,
    pub pid: Option<u64>,
    pub end_ns: Option<u64>,
    pub ok: Option<bool>,
    pub maxrss_kib: Option<u64>,
    pub children_maxrss_kib: Option<u64>,
    /// The summary line's arguments, verbatim.
    pub summary: Option<Value>,
}

/// The facts of the attempt's final receipt the harness uses.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct ReceiptFacts {
    pub attempt_id: String,
    pub phase: String,
    pub policy_name: Option<String>,
    pub policy_observe: Option<String>,
    pub outcome_kind: String,
    pub outcome_code: Option<i64>,
    pub outcome_cause: Option<String>,
    pub errors: Vec<String>,
    pub integrity: Option<String>,
    pub tree_empty: Option<bool>,
    pub observer_attached: bool,
    pub observer_gaps: usize,
    pub observer_lost: u64,
    pub coverage: BTreeMap<String, ClassFacts>,
    pub supervisor_scope: Option<String>,
    pub leaf_path: Option<String>,
    pub state_cleanup: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct ClassFacts {
    pub status: String,
    pub observed_count: Option<u64>,
    pub gaps: usize,
    pub lost: u64,
}

/// Why a launch is not counted.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// `perf-launch` did not run or wrote no result.
    LaunchFailed,
    /// The launched program never replaced the launcher's child.
    ExecFailed,
    /// The per-launch deadline passed.
    TimedOut,
    /// The target printed no `perf-start` line.
    NoStartLine,
    /// The target printed no summary line.
    NoEndLine,
    /// The target's own summary says its workload did not complete.
    WorkloadFailed,
    /// The launcher's and the target's clocks cannot be shown to be one:
    /// different or unknown time namespaces.
    ClockNamespace,
    /// The readings are not in the order launch, entry, end, reap.
    ClockOrder,
    /// Direct execution did not exit 0.
    DirectExit,
    /// Not exactly one attempt directory after a jailed launch.
    AttemptCount,
    /// The attempt left no readable receipt.
    NoReceipt,
    /// The final receipt is not `settled`.
    NotSettled,
    /// The receipt names another profile or observation mode than the arm.
    PolicyMismatch,
    /// The supervisor's scope step is not the session's one.
    SessionMismatch,
    /// The outcome is neither `exited 0` nor the recorded observe-off
    /// exec-confirmation limit.
    Outcome,
    /// The jail's own exit does not match the outcome.
    JailExit,
    /// The receipt records errors.
    Errors,
    /// Tree death is not verified.
    TreeNotVerified,
    /// A coverage class is degraded.
    CoverageDegraded,
    /// A coverage class records gaps.
    CoverageGaps,
    /// The observer records gaps.
    ObserverGaps,
    /// Observation on, and no observer attached.
    ObserverDetached,
    /// Observation on, and a closed-set class is not active.
    ClassNotActive,
    /// The trace is not a complete transcript ending on the final receipt's
    /// note (jail-v1 §13.3).
    TraceIncomplete,
}

/// Something a valid launch carries that a reader must see.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Flag {
    /// Observation off, a target that ended before the supervisor confirmed
    /// its exec: the receipt's outcome is `unknown` with the recorded cause
    /// and the jail exits nonzero, while the target's own lines prove it ran.
    ExecUnconfirmed,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Validity {
    pub valid: bool,
    pub reasons: Vec<Reason>,
    pub flags: Vec<Flag>,
}

/// One launch, as `launches.ndjson` holds it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LaunchRecord {
    pub schema: String,
    pub session: Session,
    pub workload: Workload,
    pub arm: Arm,
    pub round: u32,
    pub warmup: bool,
    #[serde(default)]
    pub launch_error: Option<String>,
    #[serde(default)]
    pub launcher: Option<LauncherFacts>,
    #[serde(default)]
    pub target: TargetFacts,
    #[serde(default)]
    pub receipt: Option<ReceiptFacts>,
    #[serde(default)]
    pub kept_attempt: Option<String>,
    /// The 1-minute load average read just before the launch.
    #[serde(default)]
    pub load1_before: Option<f64>,
    #[serde(default)]
    pub stderr_tail: Option<String>,
    #[serde(default)]
    pub validity: Validity,
}

impl LaunchRecord {
    #[must_use]
    pub fn new(session: Session, workload: Workload, arm: Arm, round: u32, warmup: bool) -> Self {
        LaunchRecord {
            schema: RECORD_SCHEMA.to_owned(),
            session,
            workload,
            arm,
            round,
            warmup,
            launch_error: None,
            launcher: None,
            target: TargetFacts::default(),
            receipt: None,
            kept_attempt: None,
            load1_before: None,
            stderr_tail: None,
            validity: Validity::default(),
        }
    }
}

/// The target's lines from its stdout.
#[must_use]
pub fn target_facts(stdout: &[u8], workload: Workload) -> TargetFacts {
    let mut facts = TargetFacts::default();
    for line in stdout.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let Ok(v) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        facts.lines += 1;
        let args = &v["args"];
        match v["op"].as_str() {
            Some("perf-start") if facts.start_ns.is_none() => {
                facts.start_ns = args["monotonic_ns"].as_u64();
                facts.timens = args["timens"].as_str().map(str::to_owned);
                facts.pid = args["pid"].as_u64();
            }
            Some(op) if op == workload.end_op() && facts.summary.is_none() => {
                facts.end_ns = args["end_ns"].as_u64();
                facts.ok = args["ok"].as_bool();
                facts.maxrss_kib = args["maxrss_kib"].as_u64();
                facts.children_maxrss_kib = args["children_maxrss_kib"].as_u64();
                facts.summary = Some(args.clone());
            }
            _ => {}
        }
    }
    facts
}

/// The facts of a receipt document.
///
/// # Errors
/// When the document is not a receipt with a phase and an outcome.
pub fn receipt_facts(r: &Value) -> Result<ReceiptFacts, String> {
    let text = |v: &Value| v.as_str().map(str::to_owned);
    let gaps_of = |v: &Value| v.as_array().map_or(0, Vec::len);
    let lost_of = |v: &Value| {
        v.as_array().map_or(0, |gaps| {
            gaps.iter()
                .filter_map(|g| g["lost_count"].as_u64())
                .sum::<u64>()
        })
    };
    let phase = text(&r["phase"]).ok_or("the receipt has no phase")?;
    let outcome_kind = text(&r["outcome"]["kind"]).ok_or("the receipt has no outcome kind")?;
    let mut coverage = BTreeMap::new();
    if let Some(classes) = r["coverage"].as_object() {
        for (name, c) in classes {
            coverage.insert(
                name.clone(),
                ClassFacts {
                    status: text(&c["status"]).unwrap_or_default(),
                    observed_count: c["observed_count"].as_u64(),
                    gaps: gaps_of(&c["gaps"]),
                    lost: lost_of(&c["gaps"]),
                },
            );
        }
    }
    let details = &r["lifetime"]["native"]["details"];
    Ok(ReceiptFacts {
        attempt_id: text(&r["attempt_id"]).unwrap_or_default(),
        phase,
        policy_name: text(&r["policy"]["name"]),
        policy_observe: text(&r["policy"]["observe"]),
        outcome_kind,
        outcome_code: r["outcome"]["code"].as_i64(),
        outcome_cause: text(&r["outcome"]["cause"]),
        errors: r["errors"].as_array().map_or_else(Vec::new, |errors| {
            errors
                .iter()
                .map(|e| e["code"].as_str().unwrap_or("?").to_owned())
                .collect()
        }),
        integrity: text(&r["lifetime"]["integrity"]),
        tree_empty: r["lifetime"]["tree_empty"].as_bool(),
        observer_attached: r["observer"]["attached"].as_bool().unwrap_or(false),
        observer_gaps: gaps_of(&r["observer"]["gaps"]),
        observer_lost: lost_of(&r["observer"]["gaps"]),
        coverage,
        supervisor_scope: text(&details["supervisor_scope"]["state"]),
        leaf_path: text(&details["execution_cgroup"]["path"]),
        state_cleanup: text(&r["state_cleanup"]),
    })
}

// ------------------------------------------------------------------ validity

/// Decide whether a launch counts. Every reason that applies is listed.
#[must_use]
pub fn validate(rec: &LaunchRecord) -> Validity {
    let mut reasons = Vec::new();
    let mut flags = Vec::new();
    if rec.launch_error.is_some() {
        reasons.push(Reason::LaunchFailed);
    }
    let Some(l) = &rec.launcher else {
        if !reasons.contains(&Reason::LaunchFailed) {
            reasons.push(Reason::LaunchFailed);
        }
        return Validity {
            valid: false,
            reasons,
            flags,
        };
    };
    if l.exec_errno.is_some() {
        reasons.push(Reason::ExecFailed);
    }
    if l.timed_out || l.wait_errno.is_some() {
        reasons.push(Reason::TimedOut);
    }
    let t = &rec.target;
    if t.start_ns.is_none() {
        reasons.push(Reason::NoStartLine);
    }
    if t.end_ns.is_none() {
        reasons.push(Reason::NoEndLine);
    }
    if t.end_ns.is_some() && t.ok != Some(true) {
        reasons.push(Reason::WorkloadFailed);
    }
    if t.start_ns.is_some() && (l.timens.is_none() || t.timens != l.timens) {
        reasons.push(Reason::ClockNamespace);
    }
    if let (Some(start), Some(end)) = (t.start_ns, t.end_ns)
        && !(l.t0_ns <= start && start <= end && end <= l.t1_ns)
    {
        reasons.push(Reason::ClockOrder);
    }
    match rec.arm {
        Arm::Direct => {
            if !(l.status.exited && l.status.code == Some(0)) {
                reasons.push(Reason::DirectExit);
            }
        }
        Arm::Jailed(profile, observe) => {
            validate_jailed(rec, l, profile, observe, &mut reasons, &mut flags);
        }
    }
    reasons.sort();
    reasons.dedup();
    Validity {
        valid: reasons.is_empty(),
        reasons,
        flags,
    }
}

fn validate_jailed(
    rec: &LaunchRecord,
    l: &LauncherFacts,
    profile: Profile,
    observe: Observe,
    reasons: &mut Vec<Reason>,
    flags: &mut Vec<Flag>,
) {
    let attempts = l.attempts.as_deref().unwrap_or(&[]);
    if attempts.len() != 1 {
        reasons.push(Reason::AttemptCount);
    }
    match attempts.first().map(|a| &a.trace) {
        Some(trace)
            if trace.error.is_none() && trace.state == "complete" && trace.guard.is_none() => {}
        _ => reasons.push(Reason::TraceIncomplete),
    }
    let Some(r) = &rec.receipt else {
        reasons.push(Reason::NoReceipt);
        return;
    };
    if r.phase != "settled" {
        reasons.push(Reason::NotSettled);
    }
    if r.policy_name.as_deref() != Some(profile.name())
        || r.policy_observe.as_deref() != Some(observe.name())
    {
        reasons.push(Reason::PolicyMismatch);
    }
    if r.supervisor_scope.as_deref() != Some(rec.session.expected_scope_state()) {
        reasons.push(Reason::SessionMismatch);
    }
    let exited_zero = r.outcome_kind == "exited" && r.outcome_code == Some(0);
    let unconfirmed = observe == Observe::Off
        && r.outcome_kind == "unknown"
        && r.outcome_cause.as_deref() == Some(EXEC_UNCONFIRMED);
    if exited_zero {
        if !(l.status.exited && l.status.code == Some(0)) {
            reasons.push(Reason::JailExit);
        }
    } else if unconfirmed {
        flags.push(Flag::ExecUnconfirmed);
        // The jail ends on its own with a nonzero code; a signal death or
        // the usage/internal code 125 is not that.
        if !(l.status.exited && l.status.code.is_some_and(|c| c != 0 && c != 125)) {
            reasons.push(Reason::JailExit);
        }
    } else {
        reasons.push(Reason::Outcome);
    }
    if !r.errors.is_empty() {
        reasons.push(Reason::Errors);
    }
    if r.integrity.as_deref() != Some("verified") || r.tree_empty != Some(true) {
        reasons.push(Reason::TreeNotVerified);
    }
    if r.coverage.values().any(|c| c.status == "degraded") {
        reasons.push(Reason::CoverageDegraded);
    }
    if r.coverage.values().any(|c| c.gaps > 0) {
        reasons.push(Reason::CoverageGaps);
    }
    if r.observer_gaps > 0 {
        reasons.push(Reason::ObserverGaps);
    }
    if observe == Observe::On {
        if !r.observer_attached {
            reasons.push(Reason::ObserverDetached);
        }
        if CLOSED_SET
            .iter()
            .any(|class| r.coverage.get(*class).is_none_or(|c| c.status != "active"))
        {
            reasons.push(Reason::ClassNotActive);
        }
    }
}

/// The timings of one launch, in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timings {
    /// Launcher's reading before fork to the target's reading at entry.
    pub startup: u64,
    /// Launcher's reading before fork to its reading after the reap.
    pub wall: u64,
    /// The target's end reading minus its entry reading.
    pub work: u64,
    /// The launcher's reading after the reap minus the target's end reading.
    pub teardown: u64,
}

/// The timings, when the four readings exist and are ordered.
#[must_use]
pub fn timings(rec: &LaunchRecord) -> Option<Timings> {
    let l = rec.launcher.as_ref()?;
    let (start, end) = (rec.target.start_ns?, rec.target.end_ns?);
    if !(l.t0_ns <= start && start <= end && end <= l.t1_ns) {
        return None;
    }
    Some(Timings {
        startup: start - l.t0_ns,
        wall: l.t1_ns - l.t0_ns,
        work: end - start,
        teardown: l.t1_ns - end,
    })
}

// ---------------------------------------------------------------- statistics

/// The middle value of sorted data; the mean of the two middle values for
/// an even count.
#[must_use]
pub fn median(sorted: &[f64]) -> Option<f64> {
    let n = sorted.len();
    if n == 0 {
        return None;
    }
    Some(if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    })
}

/// The 95th percentile by nearest rank: the ⌈0.95·n⌉-th smallest value.
/// Always an observed value; for n = 30 it is the 29th smallest.
#[must_use]
pub fn p95(sorted: &[f64]) -> Option<f64> {
    let n = sorted.len();
    if n == 0 {
        return None;
    }
    // ⌈0.95·n⌉ in integers: ⌈95n/100⌉.
    let rank = (95 * n).div_ceil(100).max(1);
    Some(sorted[rank - 1])
}

/// A distribution's summary.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Dist {
    pub n: usize,
    pub median: f64,
    pub p95: f64,
    pub min: f64,
    pub max: f64,
}

/// Summarise finite values; `None` for none.
#[must_use]
pub fn dist(values: impl IntoIterator<Item = f64>) -> Option<Dist> {
    let mut v: Vec<f64> = values.into_iter().filter(|x| x.is_finite()).collect();
    v.sort_by(f64::total_cmp);
    Some(Dist {
        n: v.len(),
        median: median(&v)?,
        p95: p95(&v)?,
        min: *v.first()?,
        max: *v.last()?,
    })
}

fn ms(ns: u64) -> f64 {
    ns as f64 / 1e6
}

// ------------------------------------------------------------------- summary

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Losses {
    /// Over every measured launch of the arm, valid or not.
    pub launches: usize,
    pub observer_gaps: u64,
    pub observer_lost: u64,
    pub coverage_gaps: u64,
    pub coverage_lost: u64,
    pub receipt_errors: u64,
    pub incomplete_traces: u64,
    pub trace_notes: BTreeMap<String, u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CellSummary {
    pub session: Session,
    pub workload: Workload,
    pub arm: Arm,
    pub launched: usize,
    pub valid: usize,
    pub excluded: usize,
    pub excluded_by_reason: BTreeMap<String, usize>,
    pub flagged: BTreeMap<String, usize>,
    pub startup_ms: Option<Dist>,
    pub wall_ms: Option<Dist>,
    pub work_ms: Option<Dist>,
    pub teardown_ms: Option<Dist>,
    /// The launched process's own sampled `VmHWM`: the supervisor for a
    /// jailed arm, the target for direct execution.
    pub launched_hwm_kib: Option<Dist>,
    /// `wait4`'s `ru_maxrss` of the launched process.
    pub reaped_tree_maxrss_kib: Option<Dist>,
    pub leaf_peak_kib: Option<Dist>,
    pub target_maxrss_kib: Option<Dist>,
    pub coverage_counts: BTreeMap<String, Dist>,
    pub trace_frames: Option<Dist>,
    pub losses: Losses,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompareKind {
    /// The jail's own overhead: the budgeted comparison (decision 2026-09-24).
    OffVsDirect,
    /// Observation included, against direct execution.
    OnVsDirect,
    /// The cost of observation alone.
    OnVsOff,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    /// Fewer than 30 valid launches on one side.
    Insufficient,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Comparison {
    pub session: Session,
    pub workload: Workload,
    pub profile: Profile,
    pub kind: CompareKind,
    pub subject: Arm,
    pub baseline: Arm,
    pub subject_valid: usize,
    pub subject_excluded: usize,
    /// Valid subject launches carrying a flag, by flag.
    pub subject_flagged: BTreeMap<String, usize>,
    pub baseline_valid: usize,
    pub baseline_excluded: usize,
    pub baseline_startup_median_ms: Option<f64>,
    pub baseline_wall_median_ms: Option<f64>,
    pub baseline_work_median_ms: Option<f64>,
    /// Per subject launch: its startup minus the baseline's median startup.
    pub added_startup_ms: Option<Dist>,
    /// Per subject launch: its wall over the baseline's median wall, minus 1.
    pub wall_overhead_pct: Option<Dist>,
    /// Per subject launch: its work phase over the baseline's median, minus 1.
    pub work_overhead_pct: Option<Dist>,
    /// p95 added startup under 250 ms; only against direct execution.
    pub startup_verdict: Option<Verdict>,
    /// Median wall overhead under 20%; fixed workload against direct only.
    pub wall_verdict: Option<Verdict>,
    /// Median work-phase overhead under 20%; fixed workload against direct only.
    pub work_verdict: Option<Verdict>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Summary {
    pub schema: String,
    pub parameters: Value,
    pub host: Value,
    pub warmup_launches: usize,
    pub cells: Vec<CellSummary>,
    pub comparisons: Vec<Comparison>,
}

type CellKey = (Session, Workload, Arm);

fn measured(records: &[LaunchRecord]) -> BTreeMap<CellKey, Vec<&LaunchRecord>> {
    let mut cells: BTreeMap<CellKey, Vec<&LaunchRecord>> = BTreeMap::new();
    for r in records.iter().filter(|r| !r.warmup) {
        cells
            .entry((r.session, r.workload, r.arm))
            .or_default()
            .push(r);
    }
    cells
}

/// The valid launches of a cell with their timings. Validity is recomputed
/// from the facts, never read back from the record.
fn valid_timed<'a>(records: &[&'a LaunchRecord]) -> Vec<(&'a LaunchRecord, Timings)> {
    records
        .iter()
        .filter(|r| validate(r).valid)
        .filter_map(|r| timings(r).map(|t| (*r, t)))
        .collect()
}

#[must_use]
pub fn summarize_cell(key: CellKey, records: &[&LaunchRecord]) -> CellSummary {
    let (session, workload, arm) = key;
    let mut excluded_by_reason: BTreeMap<String, usize> = BTreeMap::new();
    let mut flagged: BTreeMap<String, usize> = BTreeMap::new();
    let mut losses = Losses {
        launches: records.len(),
        ..Losses::default()
    };
    let mut excluded = 0;
    for r in records {
        let v = validate(r);
        if !v.valid {
            excluded += 1;
            for reason in &v.reasons {
                *excluded_by_reason.entry(enum_name(reason)).or_default() += 1;
            }
        }
        for flag in &v.flags {
            *flagged.entry(enum_name(flag)).or_default() += 1;
        }
        if let Some(rc) = &r.receipt {
            losses.observer_gaps += rc.observer_gaps as u64;
            losses.observer_lost += rc.observer_lost;
            losses.coverage_gaps += rc.coverage.values().map(|c| c.gaps as u64).sum::<u64>();
            losses.coverage_lost += rc.coverage.values().map(|c| c.lost).sum::<u64>();
            losses.receipt_errors += rc.errors.len() as u64;
        }
        if let Some(attempts) = r.launcher.as_ref().and_then(|l| l.attempts.as_ref()) {
            for a in attempts {
                if a.trace.guard.is_some() || a.trace.state != "complete" {
                    losses.incomplete_traces += 1;
                }
                for (kind, count) in &a.trace.notes {
                    *losses.trace_notes.entry(kind.clone()).or_default() += count;
                }
            }
        }
    }
    let valid = valid_timed(records);
    let over = |f: &dyn Fn(&LaunchRecord, &Timings) -> Option<f64>| {
        dist(valid.iter().filter_map(|(r, t)| f(r, t)))
    };
    let mut coverage_counts = BTreeMap::new();
    let classes: std::collections::BTreeSet<String> = valid
        .iter()
        .filter_map(|(r, _)| r.receipt.as_ref())
        .flat_map(|rc| rc.coverage.keys().cloned())
        .collect();
    for class in classes {
        let d = dist(valid.iter().filter_map(|(r, _)| {
            r.receipt
                .as_ref()?
                .coverage
                .get(&class)?
                .observed_count
                .map(|c| c as f64)
        }));
        if let Some(d) = d {
            coverage_counts.insert(class, d);
        }
    }
    CellSummary {
        session,
        workload,
        arm,
        launched: records.len(),
        valid: valid.len(),
        excluded,
        excluded_by_reason,
        flagged,
        startup_ms: over(&|_, t| Some(ms(t.startup))),
        wall_ms: over(&|_, t| Some(ms(t.wall))),
        work_ms: over(&|_, t| Some(ms(t.work))),
        teardown_ms: over(&|_, t| Some(ms(t.teardown))),
        launched_hwm_kib: over(&|r, _| r.launcher.as_ref()?.sampling.hwm_kib.map(|k| k as f64)),
        reaped_tree_maxrss_kib: over(&|r, _| Some(r.launcher.as_ref()?.rusage.maxrss_kib as f64)),
        leaf_peak_kib: over(&|r, _| {
            r.launcher
                .as_ref()?
                .sampling
                .leaf_peak_bytes
                .map(|b| b as f64 / 1024.0)
        }),
        target_maxrss_kib: over(&|r, _| r.target.maxrss_kib.map(|k| k as f64)),
        coverage_counts,
        trace_frames: over(&|r, _| {
            r.launcher
                .as_ref()?
                .attempts
                .as_ref()?
                .first()
                .map(|a| a.trace.frames as f64)
        }),
        losses,
    }
}

fn enum_name<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn verdict(
    subject_valid: usize,
    baseline_valid: usize,
    value: Option<f64>,
    budget: f64,
) -> Verdict {
    match value {
        _ if subject_valid < SPEC_MIN_LAUNCHES || baseline_valid < SPEC_MIN_LAUNCHES => {
            Verdict::Insufficient
        }
        Some(v) if v < budget => Verdict::Pass,
        Some(_) => Verdict::Fail,
        None => Verdict::Insufficient,
    }
}

fn flagged(valid: &[(&LaunchRecord, Timings)]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for (r, _) in valid {
        for flag in validate(r).flags {
            *out.entry(enum_name(&flag)).or_default() += 1;
        }
    }
    out
}

/// One comparison of a subject arm against a baseline arm of the same
/// session and workload.
#[must_use]
pub fn compare(
    session: Session,
    workload: Workload,
    profile: Profile,
    kind: CompareKind,
    subject: (Arm, &[&LaunchRecord]),
    baseline: (Arm, &[&LaunchRecord]),
) -> Comparison {
    let s = valid_timed(subject.1);
    let b = valid_timed(baseline.1);
    let sorted = |f: &dyn Fn(&Timings) -> u64| {
        let mut v: Vec<f64> = b.iter().map(|(_, t)| ms(f(t))).collect();
        v.sort_by(f64::total_cmp);
        median(&v)
    };
    let b_startup = sorted(&|t| t.startup);
    let b_wall = sorted(&|t| t.wall);
    let b_work = sorted(&|t| t.work);
    let added = b_startup.and_then(|base| dist(s.iter().map(|(_, t)| ms(t.startup) - base)));
    let ratio = |base: Option<f64>, f: &dyn Fn(&Timings) -> u64| {
        base.filter(|b| *b > 0.0)
            .and_then(|base| dist(s.iter().map(|(_, t)| (ms(f(t)) / base - 1.0) * 100.0)))
    };
    let wall = ratio(b_wall, &|t| t.wall);
    let work = ratio(b_work, &|t| t.work);
    let against_direct = baseline.0 == Arm::Direct;
    let fixed = workload == Workload::Fileops;
    let excluded =
        |records: &[&LaunchRecord]| records.iter().filter(|r| !validate(r).valid).count();
    Comparison {
        session,
        workload,
        profile,
        kind,
        subject: subject.0,
        baseline: baseline.0,
        subject_valid: s.len(),
        subject_excluded: excluded(subject.1),
        subject_flagged: flagged(&s),
        baseline_valid: b.len(),
        baseline_excluded: excluded(baseline.1),
        baseline_startup_median_ms: b_startup,
        baseline_wall_median_ms: b_wall,
        baseline_work_median_ms: b_work,
        startup_verdict: against_direct.then(|| {
            verdict(
                s.len(),
                b.len(),
                added.as_ref().map(|d| d.p95),
                STARTUP_BUDGET_MS,
            )
        }),
        wall_verdict: (against_direct && fixed).then(|| {
            verdict(
                s.len(),
                b.len(),
                wall.as_ref().map(|d| d.median),
                OVERHEAD_BUDGET_PCT,
            )
        }),
        work_verdict: (against_direct && fixed).then(|| {
            verdict(
                s.len(),
                b.len(),
                work.as_ref().map(|d| d.median),
                OVERHEAD_BUDGET_PCT,
            )
        }),
        added_startup_ms: added,
        wall_overhead_pct: wall,
        work_overhead_pct: work,
    }
}

/// The whole summary of a set of launch records.
#[must_use]
pub fn summarize(records: &[LaunchRecord], parameters: Value, host: Value) -> Summary {
    let cells = measured(records);
    let empty: Vec<&LaunchRecord> = Vec::new();
    let get = |k: CellKey| cells.get(&k).map_or(empty.as_slice(), Vec::as_slice);
    let mut comparisons = Vec::new();
    let mut groups: Vec<(Session, Workload, Profile)> = cells
        .keys()
        .filter_map(|(s, w, a)| match a {
            Arm::Jailed(p, _) => Some((*s, *w, *p)),
            Arm::Direct => None,
        })
        .collect();
    groups.sort();
    groups.dedup();
    for (session, workload, profile) in groups {
        let off = Arm::Jailed(profile, Observe::Off);
        let on = Arm::Jailed(profile, Observe::On);
        for (kind, subject, baseline) in [
            (CompareKind::OffVsDirect, off, Arm::Direct),
            (CompareKind::OnVsDirect, on, Arm::Direct),
            (CompareKind::OnVsOff, on, off),
        ] {
            comparisons.push(compare(
                session,
                workload,
                profile,
                kind,
                (subject, get((session, workload, subject))),
                (baseline, get((session, workload, baseline))),
            ));
        }
    }
    Summary {
        schema: SUMMARY_SCHEMA.to_owned(),
        parameters,
        host,
        warmup_launches: records.iter().filter(|r| r.warmup).count(),
        cells: cells.iter().map(|(k, v)| summarize_cell(*k, v)).collect(),
        comparisons,
    }
}

// ------------------------------------------------------------------ markdown

fn num(v: Option<f64>, digits: usize) -> String {
    v.map_or_else(|| "n/a".to_owned(), |x| format!("{x:.digits$}"))
}

fn pair(d: Option<&Dist>, digits: usize, unit: &str) -> String {
    d.map_or_else(
        || "n/a".to_owned(),
        |d| format!("{:.digits$} / {:.digits$}{unit}", d.median, d.p95),
    )
}

fn med_max(d: Option<&Dist>) -> String {
    d.map_or_else(
        || "n/a".to_owned(),
        |d| format!("{:.0} / {:.0}", d.median, d.max),
    )
}

fn verdict_text(v: Option<Verdict>, value: Option<f64>, unit: &str) -> String {
    match v {
        None => "n/a".to_owned(),
        Some(v) => format!("{} ({}{unit})", enum_name(&v), num(value, 1)),
    }
}

fn reasons_text(map: &BTreeMap<String, usize>) -> String {
    if map.is_empty() {
        return "none".to_owned();
    }
    map.iter()
        .map(|(k, v)| format!("{k} {v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn host_line(host: &Value) -> String {
    let s = |p: &str| host.pointer(p).and_then(Value::as_str).unwrap_or("unknown");
    format!(
        "Collected {} on `{}` ({}, kernel {}, {} CPUs, {} MiB) as `{}` (lingering: {}). \
         Revision `{}`. `ouro-jail` sha256 `{}`; `ouro-fixture` sha256 `{}`; {}.",
        s("/collected_at"),
        s("/hostname"),
        s("/os_release"),
        s("/kernel"),
        host["cpus"]
            .as_u64()
            .map_or("?".to_owned(), |n| n.to_string()),
        host["mem_total_kib"]
            .as_u64()
            .map_or("?".to_owned(), |k| (k / 1024).to_string()),
        s("/user"),
        host["linger"]
            .as_bool()
            .map_or("unknown", |b| if b { "yes" } else { "no" }),
        s("/revision"),
        s("/jail/sha256"),
        s("/fixture/sha256"),
        s("/bwrap_version").trim(),
    )
}

const DEFINITIONS: &str = "\
## Definitions

- **Launcher.** `ouro-fixture perf-launch`, outside the jail, forks the arm's \
command: the workload itself (direct) or `ouro-jail run --profile P --observe \
on|off --workspace WS -- workload`. It reads `CLOCK_MONOTONIC` just before \
`fork` and again after `wait4` returns.
- **Startup.** From that first reading to the target's own first reading at \
entry to its workload mode (after its exec, dynamic loading and argument \
parsing, the same for every arm). The target reports its time namespace and \
the launcher its own; a launch where they differ or are unknown is excluded. \
For a jailed arm startup includes the supervisor's own start, the scope step \
(plain session), the capability probes, preparation, bubblewrap, observer \
attachment and the exec.
- **Added warm startup.** A jailed launch's startup minus the median startup \
of the direct arm of the same session and workload. Warm: after the discarded \
warm-up launch of every arm.
- **Wall.** The launcher's two readings: spawn to the jail's exit, after \
settlement and the final receipt.
- **Work.** The target's end reading minus its entry reading: the workload \
phase alone, where the observer's per-call cost falls.
- **Teardown.** Wall end minus the target's end reading.
- **Overhead.** A launch's wall (or work) over the baseline arm's median, minus \
one. The median of these is the ratio of medians minus one.
- **Median / p95.** The middle value (mean of the two middle values for an \
even count); p95 by nearest rank, the ⌈0.95·n⌉-th smallest value (the 29th of \
30).
- **Peak RSS.** Launched HWM: the launched process's own `VmHWM` (the \
supervisor for a jailed arm), sampled every interval, last sample (a lower \
bound). Reaped tree: `wait4`'s `ru_maxrss`, the largest resident set of the \
launched process and anything it reaped (for a jailed arm the supervisor, \
bubblewrap and whatever they reaped). Leaf: the execution leaf's \
`memory.peak` (cgroup memory including page cache), sampled, last sample. \
Target: the target's own `ru_maxrss` at its end.
- **Validity.** A launch counts only if the launcher ran and exec'd, the \
target printed both lines and completed its workload, one clock and ordered \
readings, direct execution exited 0; and for a jailed arm: exactly one \
attempt, a settled final receipt of the arm's profile and observation mode, \
the session's scope state (`entered` from a plain session, \
`already_delegated` in a scope), outcome `exited 0` (or, with observation \
off, the recorded exec-confirmation limit, flagged), no receipt error, tree \
death verified, no degraded class, no coverage or observer gap, with \
observation on an attached observer and every closed-set class active, and a \
trace that is complete and ends on the final receipt's note (§13.3). \
Everything else is excluded, counted by reason and never averaged.
- **Verdicts.** Against direct execution only. `insufficient` below 30 valid \
launches on either side.
";

/// The Markdown report.
#[must_use]
pub fn render_markdown(summary: &Summary) -> String {
    let mut md = String::new();
    let p = &summary.parameters;
    let _ = writeln!(md, "# `ouro-jail` performance (jail-v1 §5)\n");
    let _ = writeln!(md, "{}\n", host_line(&summary.host));
    let _ = writeln!(
        md,
        "Parameters: {} measured launch(es) per arm after {} warm-up launch(es) per arm \
         ({} warm-up records discarded); sessions {}; profiles {}; workloads {}; fileops \
         {} rounds; spawn-tree {} children; sampling every {} ms. Arm order rotates by one \
         each round.\n",
        p["launches"],
        p["warmup"],
        summary.warmup_launches,
        p["sessions"],
        p["profiles"],
        p["workloads"],
        p["fileops_rounds"],
        p["spawn_count"],
        p["sample_ms"],
    );
    let short = summary.cells.iter().any(|c| c.valid < SPEC_MIN_LAUNCHES)
        || summary
            .comparisons
            .iter()
            .any(|c| c.subject_valid < SPEC_MIN_LAUNCHES || c.baseline_valid < SPEC_MIN_LAUNCHES);
    if short {
        let _ = writeln!(
            md,
            "**Not the §5 measurement:** at least one arm has fewer than {SPEC_MIN_LAUNCHES} \
             valid launches, so every verdict it touches is `insufficient`; the numbers are \
             provisional.\n"
        );
    }

    let _ = writeln!(
        md,
        "## Budgets: the jail's own overhead (`tool`, `--observe off` against direct)\n\n\
         The budgeted comparison under the decision of 2026-09-24. Each cell: median / p95 \
         over the valid launches. `exec_unconfirmed` marks valid launches whose receipt \
         outcome is `unknown` because, with observation off, the target ended before the \
         supervisor confirmed its exec (the jail then exits 1); the target's own lines \
         prove it ran, and the timing is the jail's real path.\n"
    );
    comparison_table(
        &mut md,
        summary,
        Some(Profile::Tool),
        CompareKind::OffVsDirect,
        true,
    );

    let _ = writeln!(
        md,
        "## Observation cost (reported, not budgeted)\n\n\
         ### Observation on against observation off\n"
    );
    comparison_table(&mut md, summary, None, CompareKind::OnVsOff, false);
    let _ = writeln!(
        md,
        "### Observation on against direct (the original budgets with observation)\n"
    );
    comparison_table(&mut md, summary, None, CompareKind::OnVsDirect, true);
    let _ = writeln!(
        md,
        "## Informational profiles: `--observe off` against direct\n"
    );
    for profile in [Profile::Agent, Profile::None] {
        comparison_table(
            &mut md,
            summary,
            Some(profile),
            CompareKind::OffVsDirect,
            true,
        );
    }

    let _ = writeln!(md, "## Per arm\n");
    let _ = writeln!(
        md,
        "| Session | Workload | Arm | Valid | Excluded (reasons) | Flagged | Startup ms | Wall ms | \
         Work ms | Teardown ms |\n|---|---|---|---|---|---|---|---|---|---|"
    );
    for c in &summary.cells {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {}/{} | {} ({}) | {} | {} | {} | {} | {} |",
            c.session.name(),
            c.workload.name(),
            c.arm.name(),
            c.valid,
            c.launched,
            c.excluded,
            reasons_text(&c.excluded_by_reason),
            reasons_text(&c.flagged),
            pair(c.startup_ms.as_ref(), 1, ""),
            pair(c.wall_ms.as_ref(), 1, ""),
            pair(c.work_ms.as_ref(), 1, ""),
            pair(c.teardown_ms.as_ref(), 1, ""),
        );
    }
    let _ = writeln!(
        md,
        "\n### Peak memory (KiB, median / max over valid launches)\n\n\
         | Session | Workload | Arm | Launched HWM (sampled) | Reaped tree (`wait4`) | \
         Leaf `memory.peak` (sampled) | Target |\n|---|---|---|---|---|---|---|"
    );
    for c in &summary.cells {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} | {} |",
            c.session.name(),
            c.workload.name(),
            c.arm.name(),
            med_max(c.launched_hwm_kib.as_ref()),
            med_max(c.reaped_tree_maxrss_kib.as_ref()),
            med_max(c.leaf_peak_kib.as_ref()),
            med_max(c.target_maxrss_kib.as_ref()),
        );
    }
    let _ = writeln!(
        md,
        "\n### Events and losses\n\n\
         Event counts: the receipt's `coverage.<class>.observed_count`, median over valid \
         launches. Losses: over every measured launch of the arm, valid or not.\n\n\
         | Session | Workload | Arm | exec | fs.write | fs.deny | net | proxy.net | Trace \
         frames | Observer gaps (lost) | Coverage gaps (lost) | Receipt errors | Incomplete \
         traces | Trace notes (all kinds) |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
    );
    for c in summary.cells.iter().filter(|c| c.arm != Arm::Direct) {
        let count = |k: &str| num(c.coverage_counts.get(k).map(|d| d.median), 0);
        let l = &c.losses;
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} ({}) | {} ({}) | {} | {} | {} |",
            c.session.name(),
            c.workload.name(),
            c.arm.name(),
            count("exec"),
            count("fs.write"),
            count("fs.deny"),
            count("net"),
            count("proxy.net"),
            num(c.trace_frames.as_ref().map(|d| d.median), 0),
            l.observer_gaps,
            l.observer_lost,
            l.coverage_gaps,
            l.coverage_lost,
            l.receipt_errors,
            l.incomplete_traces,
            reasons_text(
                &l.trace_notes
                    .iter()
                    .map(|(k, v)| (k.clone(), *v as usize))
                    .collect()
            ),
        );
    }

    let _ = writeln!(
        md,
        "\n## backend-evaluation.md §4, `tool`\n\n\
         Startup: p95 added against direct. Wall: median overhead against direct (work phase \
         in brackets). Peak RSS: supervisor sampled HWM median (KiB). Events: median trace \
         frames. Losses: observer + coverage gaps over all launches.\n"
    );
    for session in [Session::Plain, Session::Scope] {
        let rows: Vec<&Comparison> = summary
            .comparisons
            .iter()
            .filter(|c| {
                c.session == session
                    && c.profile == Profile::Tool
                    && matches!(c.kind, CompareKind::OffVsDirect | CompareKind::OnVsDirect)
            })
            .collect();
        if rows.is_empty() {
            continue;
        }
        let _ = writeln!(
            md,
            "{} session:\n\n| Workload | Observe | Startup p95 added | Wall median overhead | \
             Peak RSS | Event count | Losses |\n|---|---|---|---|---|---|---|",
            session.name()
        );
        for c in rows {
            let cell = summary
                .cells
                .iter()
                .find(|x| x.session == c.session && x.workload == c.workload && x.arm == c.subject);
            let observe = match c.subject {
                Arm::Jailed(_, o) => o.name(),
                Arm::Direct => "-",
            };
            let _ = writeln!(
                md,
                "| {} | {} | {} ms | {}% ({}%) | {} | {} | {} |",
                c.workload.name(),
                observe,
                num(c.added_startup_ms.as_ref().map(|d| d.p95), 1),
                num(c.wall_overhead_pct.as_ref().map(|d| d.median), 1),
                num(c.work_overhead_pct.as_ref().map(|d| d.median), 1),
                num(
                    cell.and_then(|x| x.launched_hwm_kib.as_ref())
                        .map(|d| d.median),
                    0
                ),
                num(
                    cell.and_then(|x| x.trace_frames.as_ref()).map(|d| d.median),
                    0
                ),
                cell.map_or(0, |x| x.losses.observer_gaps + x.losses.coverage_gaps),
            );
        }
        let _ = writeln!(md);
    }
    md.push_str(DEFINITIONS);
    md
}

fn comparison_table(
    md: &mut String,
    summary: &Summary,
    profile: Option<Profile>,
    kind: CompareKind,
    verdicts: bool,
) {
    let rows: Vec<&Comparison> = summary
        .comparisons
        .iter()
        .filter(|c| c.kind == kind && profile.is_none_or(|p| c.profile == p))
        .collect();
    if rows.is_empty() {
        let _ = writeln!(md, "(no data)\n");
        return;
    }
    let _ = write!(
        md,
        "| Session | Profile | Workload | Subject / baseline | Valid (excl.) subject | Valid \
         (excl.) baseline | Baseline median startup / wall / work ms | Added startup ms | Wall \
         overhead % | Work overhead % |"
    );
    if verdicts {
        let _ = write!(
            md,
            " p95 added startup < 250 ms | Median wall overhead < 20% | Median work overhead < 20% |"
        );
    }
    let _ = writeln!(md);
    let cols = if verdicts { 13 } else { 10 };
    let _ = writeln!(md, "|{}", "---|".repeat(cols));
    for c in rows {
        let _ = write!(
            md,
            "| {} | {} | {} | {} / {} | {} ({}) | {} ({}) | {} / {} / {} | {} | {} | {} |",
            c.session.name(),
            c.profile.name(),
            c.workload.name(),
            c.subject.name(),
            c.baseline.name(),
            c.subject_valid,
            if c.subject_flagged.is_empty() {
                c.subject_excluded.to_string()
            } else {
                format!(
                    "{}; flagged: {}",
                    c.subject_excluded,
                    reasons_text(&c.subject_flagged)
                )
            },
            c.baseline_valid,
            c.baseline_excluded,
            num(c.baseline_startup_median_ms, 1),
            num(c.baseline_wall_median_ms, 1),
            num(c.baseline_work_median_ms, 1),
            pair(c.added_startup_ms.as_ref(), 1, ""),
            pair(c.wall_overhead_pct.as_ref(), 1, ""),
            pair(c.work_overhead_pct.as_ref(), 1, ""),
        );
        if verdicts {
            let _ = write!(
                md,
                " {} | {} | {} |",
                verdict_text(
                    c.startup_verdict,
                    c.added_startup_ms.as_ref().map(|d| d.p95),
                    " ms"
                ),
                verdict_text(
                    c.wall_verdict,
                    c.wall_overhead_pct.as_ref().map(|d| d.median),
                    "%"
                ),
                verdict_text(
                    c.work_verdict,
                    c.work_overhead_pct.as_ref().map(|d| d.median),
                    "%"
                ),
            );
        }
        let _ = writeln!(md);
    }
    let _ = writeln!(md);
}

// -------------------------------------------------------------------- runner

/// Entry point for `cargo xtask perf`.
#[must_use]
pub fn main(cli: Cli) -> ExitCode {
    let result = match cli.action {
        Action::Run(args) => run(*args),
        Action::Summarize { dir } => write_summary(&dir).map(|md| {
            println!("{md}");
        }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask perf: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The resolved inputs of a run.
struct Plan {
    args: RunArgs,
    out: PathBuf,
    jail: PathBuf,
    fixture: PathBuf,
}

fn absolute(p: &Path) -> Result<PathBuf, String> {
    if p.is_absolute() {
        return Ok(p.to_path_buf());
    }
    let cwd = std::env::current_dir().map_err(|e| format!("current directory: {e}"))?;
    Ok(cwd.join(p))
}

fn resolve(args: &RunArgs) -> Result<Plan, String> {
    let jail = absolute(
        args.jail
            .as_deref()
            .unwrap_or(Path::new("target/release/ouro-jail")),
    )?;
    let fixture = absolute(
        args.fixture
            .as_deref()
            .unwrap_or(Path::new("target/release/ouro-fixture")),
    )?;
    for (name, p) in [("ouro-jail", &jail), ("ouro-fixture", &fixture)] {
        if !p.is_file() {
            return Err(format!(
                "{name} is not at {}; build it with `cargo build --release -p ouro-jail -p \
                 ouro-fixture` or name it with --{}",
                p.display(),
                if name == "ouro-jail" {
                    "jail"
                } else {
                    "fixture"
                }
            ));
        }
    }
    let out = match (&args.inner, &args.out) {
        (Some(dir), _) => absolute(dir)?,
        (None, Some(dir)) => absolute(dir)?,
        (None, None) => absolute(
            &Path::new("evidence").join(format!("perf-{}", crate::stamp::utc_stamp_now())),
        )?,
    };
    if args.launches == 0 {
        return Err("--launches must be at least 1".to_owned());
    }
    Ok(Plan {
        args: args.clone(),
        out,
        jail,
        fixture,
    })
}

/// The argv the scope pass re-executes this program with.
#[must_use]
pub fn inner_argv(args: &RunArgs, out: &Path, jail: &Path, fixture: &Path) -> Vec<OsString> {
    let join = |v: Vec<&'static str>| v.join(",");
    let mut argv: Vec<OsString> = vec![
        "perf".into(),
        "run".into(),
        "--inner".into(),
        out.into(),
        "--sessions".into(),
        "scope".into(),
        "--launches".into(),
        args.launches.to_string().into(),
        "--warmup".into(),
        args.warmup.to_string().into(),
        "--profiles".into(),
        join(args.profiles.iter().map(|p| p.name()).collect()).into(),
        "--workloads".into(),
        join(args.workloads.iter().map(|w| w.name()).collect()).into(),
        "--fileops-rounds".into(),
        args.fileops_rounds.to_string().into(),
        "--spawn-count".into(),
        args.spawn_count.to_string().into(),
        "--sample-ms".into(),
        args.sample_ms.to_string().into(),
        "--deadline-ms".into(),
        args.deadline_ms.to_string().into(),
        "--jail".into(),
        jail.into(),
        "--fixture".into(),
        fixture.into(),
    ];
    if let Some(load) = args.max_load {
        argv.push("--max-load".into());
        argv.push(load.to_string().into());
    }
    if let Some(rev) = &args.revision {
        argv.push("--revision".into());
        argv.push(rev.into());
    }
    argv
}

fn parameters(plan: &Plan) -> Value {
    let a = &plan.args;
    json!({
        "launches": a.launches,
        "warmup": a.warmup,
        "sessions": a.sessions.iter().map(|s| s.name()).collect::<Vec<_>>(),
        "profiles": a.profiles.iter().map(|p| p.name()).collect::<Vec<_>>(),
        "workloads": a.workloads.iter().map(|w| w.name()).collect::<Vec<_>>(),
        "fileops_rounds": a.fileops_rounds,
        "spawn_count": a.spawn_count,
        "spawn_child": "/usr/bin/true",
        "sample_ms": a.sample_ms,
        "deadline_ms": a.deadline_ms,
        "max_load": a.max_load,
        "jail": plan.jail,
        "fixture": plan.fixture,
        "trace_sink": "the default local trace.ndjson (no --trace-fd consumer)",
        "startup_budget_ms": STARTUP_BUDGET_MS,
        "overhead_budget_pct": OVERHEAD_BUDGET_PCT,
        "spec_min_launches": SPEC_MIN_LAUNCHES,
    })
}

fn run(args: RunArgs) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("`perf run` measures on Linux; run it on the reference host".to_owned());
    }
    let plan = resolve(&args)?;
    std::fs::create_dir_all(&plan.out)
        .map_err(|e| format!("cannot create {}: {e}", plan.out.display()))?;
    if args.inner.is_some() {
        return run_passes(&plan);
    }
    write_json(&plan.out.join(PARAMETERS_FILE), &parameters(&plan))?;
    write_json(&plan.out.join(HOST_FILE), &host_facts(&plan))?;
    eprintln!("xtask perf: writing to {}", plan.out.display());
    if plan.args.sessions.contains(&Session::Plain) {
        let mut plain = plan.args.clone();
        plain.sessions = vec![Session::Plain];
        run_passes(&Plan {
            args: plain,
            out: plan.out.clone(),
            jail: plan.jail.clone(),
            fixture: plan.fixture.clone(),
        })?;
    }
    if plan.args.sessions.contains(&Session::Scope) {
        let exe = std::env::current_exe().map_err(|e| format!("this program's path: {e}"))?;
        let mut cmd = Command::new("systemd-run");
        cmd.args(["--user", "--scope", "--quiet", "--"])
            .arg(exe)
            .args(inner_argv(&plan.args, &plan.out, &plan.jail, &plan.fixture));
        if std::env::var_os("XDG_RUNTIME_DIR").is_none()
            && let Some(uid) = own_uid()
        {
            cmd.env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"));
        }
        let status = cmd
            .status()
            .map_err(|e| format!("systemd-run for the scope pass: {e}"))?;
        if !status.success() {
            return Err(format!("the scope pass failed: {status}"));
        }
    }
    let md = write_summary(&plan.out)?;
    println!("{md}");
    eprintln!(
        "xtask perf: summary in {}",
        plan.out.join("summary.md").display()
    );
    Ok(())
}

fn write_json(path: &Path, v: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_json(path: &Path) -> Value {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}

/// Read `launches.ndjson`, summarise, and write `summary.json` and
/// `summary.md`. Returns the Markdown.
fn write_summary(dir: &Path) -> Result<String, String> {
    let raw = std::fs::read(dir.join(RAW_FILE))
        .map_err(|e| format!("{}: {e}", dir.join(RAW_FILE).display()))?;
    let mut records = Vec::new();
    for (i, line) in raw
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .enumerate()
    {
        records.push(
            serde_json::from_slice::<LaunchRecord>(line)
                .map_err(|e| format!("{RAW_FILE} line {}: {e}", i + 1))?,
        );
    }
    let summary = summarize(
        &records,
        read_json(&dir.join(PARAMETERS_FILE)),
        read_json(&dir.join(HOST_FILE)),
    );
    let v = serde_json::to_value(&summary).map_err(|e| e.to_string())?;
    write_json(&dir.join("summary.json"), &v)?;
    let md = render_markdown(&summary);
    std::fs::write(dir.join("summary.md"), &md)
        .map_err(|e| format!("{}: {e}", dir.join("summary.md").display()))?;
    Ok(md)
}

fn own_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find(|l| l.starts_with("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// The unified cgroup of this process, from `/proc/self/cgroup`.
fn own_cgroup() -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_owned)
}

/// Is `cgroup` inside the user manager `user@<uid>.service`?
#[must_use]
pub fn under_user_manager(cgroup: &str, uid: u32) -> bool {
    let unit = format!("user@{uid}.service");
    cgroup.split('/').any(|c| c == unit)
}

fn loadavg() -> Option<String> {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|s| s.trim().to_owned())
}

fn load1() -> Option<f64> {
    loadavg()?.split_whitespace().next()?.parse().ok()
}

fn command_text(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        let _ = write!(
            text,
            "\n[exit {}] {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Some(text)
}

fn sha256(path: &Path) -> Option<String> {
    let text = command_text("sha256sum", &[path.to_str()?])?;
    text.split_whitespace().next().map(str::to_owned)
}

fn host_facts(plan: &Plan) -> Value {
    let read = |p: &str| std::fs::read_to_string(p).ok().map(|s| s.trim().to_owned());
    let os_release = read("/etc/os-release").and_then(|t| {
        t.lines()
            .find_map(|l| l.strip_prefix("PRETTY_NAME="))
            .map(|v| v.trim_matches('"').to_owned())
    });
    let cpus =
        read("/proc/cpuinfo").map(|t| t.lines().filter(|l| l.starts_with("processor")).count());
    let mem = read("/proc/meminfo").and_then(|t| {
        t.lines()
            .find(|l| l.starts_with("MemTotal:"))?
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()
    });
    let user = std::env::var("USER").ok();
    let linger = user
        .as_deref()
        .map(|u| Path::new("/var/lib/systemd/linger").join(u).exists());
    let jail = plan.jail.to_str().unwrap_or_default();
    let json_of = |text: Option<String>| {
        text.map_or(Value::Null, |t| {
            serde_json::from_str::<Value>(&t).unwrap_or(Value::String(t))
        })
    };
    json!({
        "collected_at": crate::stamp::rfc3339_from_unix(crate::stamp::unix_now()),
        "hostname": read("/proc/sys/kernel/hostname"),
        "kernel": read("/proc/sys/kernel/osrelease"),
        "os_release": os_release,
        "cpus": cpus,
        "mem_total_kib": mem,
        "user": user,
        "uid": own_uid(),
        "linger": linger,
        "xtask_cgroup": own_cgroup(),
        "loadavg": loadavg(),
        "revision": plan.args.revision.clone()
            .or_else(|| std::env::var("OURO_BUILD_REVISION").ok()),
        "jail": {
            "path": plan.jail,
            "sha256": sha256(&plan.jail),
            "version": json_of(command_text(jail, &["version", "--json"])),
        },
        "fixture": { "path": plan.fixture, "sha256": sha256(&plan.fixture) },
        "bwrap_version": command_text("bwrap", &["--version"]),
        "spawn_child_resolved": std::fs::canonicalize("/usr/bin/true").ok(),
        "doctor_tool": json_of(command_text(jail, &["doctor", "--json", "--profile", "tool"])),
    })
}

/// The session this process is in, checked against the one it must measure.
fn check_session(session: Session) -> Result<String, String> {
    let cgroup = own_cgroup().ok_or("cannot read /proc/self/cgroup")?;
    let uid = own_uid().ok_or("cannot read this process's uid")?;
    let inside = under_user_manager(&cgroup, uid);
    match (session, inside) {
        (Session::Plain, false) | (Session::Scope, true) => Ok(cgroup),
        (Session::Plain, true) => Err(format!(
            "the plain-session pass must start outside the user manager, from a login \
             session; this process is in {cgroup}"
        )),
        (Session::Scope, false) => Err(format!(
            "the scope pass must run inside a delegated user scope; this process is in {cgroup}"
        )),
    }
}

/// The per-arm private state of one pass.
struct ArmState {
    root: PathBuf,
    generation: u32,
}

impl ArmState {
    fn data(&self) -> PathBuf {
        self.root.join(format!("data-{}", self.generation))
    }
    fn config(&self) -> PathBuf {
        self.root.join("config")
    }
    fn prepare(&self) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt as _;
        for dir in [self.data(), self.config()] {
            std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        Ok(())
    }
}

fn run_passes(plan: &Plan) -> Result<(), String> {
    for session in &plan.args.sessions {
        run_pass(plan, *session)?;
    }
    Ok(())
}

fn append_line(path: &Path, v: &impl Serialize) -> Result<(), String> {
    let mut line = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    line.push(b'\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(&line)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn run_pass(plan: &Plan, session: Session) -> Result<(), String> {
    let cgroup = check_session(session)?;
    if let (Some(max), Some(now)) = (plan.args.max_load, load1())
        && now > max
    {
        return Err(format!(
            "the 1-minute load average is {now}, above --max-load {max}: the host is not quiet"
        ));
    }
    let started = crate::stamp::rfc3339_from_unix(crate::stamp::unix_now());
    let load_start = loadavg();
    let base = plan.out.join(session.name());
    let ws = base.join("ws");
    std::fs::create_dir_all(ws.join("fileops")).map_err(|e| format!("{}: {e}", ws.display()))?;
    let target_bin = ws.join("ouro-fixture");
    std::fs::copy(&plan.fixture, &target_bin)
        .map_err(|e| format!("copy the fixture into the workspace: {e}"))?;
    let scratch = base.join("launch");
    std::fs::create_dir_all(&scratch).map_err(|e| format!("{}: {e}", scratch.display()))?;
    let raw = plan.out.join(RAW_FILE);

    for workload in &plan.args.workloads {
        let target_argv: Vec<OsString> = match workload {
            Workload::Noop => vec![target_bin.clone().into(), "spawn-tree".into(), "0".into()],
            Workload::SpawnTree => vec![
                target_bin.clone().into(),
                "spawn-tree".into(),
                plan.args.spawn_count.to_string().into(),
                "--".into(),
                "/usr/bin/true".into(),
            ],
            Workload::Fileops => vec![
                target_bin.clone().into(),
                "fileops".into(),
                plan.args.fileops_rounds.to_string().into(),
                ws.join("fileops").into(),
            ],
        };
        let arm_list = arms(&plan.args.profiles);
        let mut states: BTreeMap<Arm, ArmState> = BTreeMap::new();
        for arm in &arm_list {
            let st = ArmState {
                root: base
                    .join("state")
                    .join(workload.name())
                    .join(arm.dir_name()),
                generation: 0,
            };
            st.prepare()?;
            states.insert(*arm, st);
        }
        let total = plan.args.warmup + plan.args.launches;
        for round in 0..total {
            let warmup = round < plan.args.warmup;
            let index = if warmup {
                round
            } else {
                round - plan.args.warmup
            };
            for arm in round_order(&arm_list, round) {
                let st = states.get_mut(&arm).ok_or("an arm without state")?;
                let rec = launch(
                    plan,
                    session,
                    *workload,
                    arm,
                    index,
                    warmup,
                    &target_argv,
                    &ws,
                    &scratch,
                    st,
                )?;
                progress(&rec);
                append_line(&raw, &rec)?;
            }
        }
    }
    append_line(
        &plan.out.join(PASSES_FILE),
        &json!({
            "session": session.name(),
            "cgroup": cgroup,
            "started": started,
            "ended": crate::stamp::rfc3339_from_unix(crate::stamp::unix_now()),
            "loadavg_start": load_start,
            "loadavg_end": loadavg(),
        }),
    )
}

fn progress(rec: &LaunchRecord) {
    let tag = format!(
        "[{} {} {} {}{}]",
        rec.session.name(),
        rec.workload.name(),
        rec.arm.name(),
        if rec.warmup { "warm-up " } else { "" },
        rec.round
    );
    match timings(rec) {
        Some(t) if rec.validity.valid => eprintln!(
            "{tag} startup {:.1} ms wall {:.1} ms work {:.1} ms{}",
            ms(t.startup),
            ms(t.wall),
            ms(t.work),
            if rec.validity.flags.is_empty() {
                String::new()
            } else {
                format!(" flags {:?}", rec.validity.flags)
            }
        ),
        _ => eprintln!("{tag} EXCLUDED {:?}", rec.validity.reasons),
    }
}

#[allow(clippy::too_many_arguments)]
fn launch(
    plan: &Plan,
    session: Session,
    workload: Workload,
    arm: Arm,
    round: u32,
    warmup: bool,
    target_argv: &[OsString],
    ws: &Path,
    scratch: &Path,
    state: &mut ArmState,
) -> Result<LaunchRecord, String> {
    let mut rec = LaunchRecord::new(session, workload, arm, round, warmup);
    rec.load1_before = load1();
    let result_path = scratch.join("result.json");
    let stdout_path = scratch.join("stdout");
    let stderr_path = scratch.join("stderr");
    let _ = std::fs::remove_file(&result_path);
    let stdout = std::fs::File::create(&stdout_path).map_err(|e| e.to_string())?;
    let stderr = std::fs::File::create(&stderr_path).map_err(|e| e.to_string())?;

    let mut cmd = Command::new(&plan.fixture);
    cmd.arg("--no-report")
        .arg("perf-launch")
        .arg("--out")
        .arg(&result_path)
        .arg("--sample-ms")
        .arg(plan.args.sample_ms.to_string())
        .arg("--deadline-ms")
        .arg(plan.args.deadline_ms.to_string());
    if let Arm::Jailed(profile, observe) = arm {
        cmd.arg("--data-dir")
            .arg(state.data())
            .env("OURO_DATA_DIR", state.data())
            .env("OURO_CONFIG_DIR", state.config())
            .arg("--")
            .arg(&plan.jail)
            .args([
                "run",
                "--profile",
                profile.name(),
                "--observe",
                observe.name(),
            ])
            .arg("--workspace")
            .arg(ws)
            .arg("--");
    } else {
        cmd.arg("--");
    }
    cmd.args(target_argv)
        .current_dir(ws)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    match cmd.status() {
        Ok(status) if status.success() => {}
        Ok(status) => rec.launch_error = Some(format!("perf-launch exited {status}")),
        Err(e) => rec.launch_error = Some(format!("perf-launch did not start: {e}")),
    }
    match std::fs::read(&result_path) {
        Ok(bytes) => match serde_json::from_slice::<LauncherFacts>(&bytes) {
            Ok(l) => rec.launcher = Some(l),
            Err(e) => {
                rec.launch_error
                    .get_or_insert(format!("the perf-launch result is unreadable: {e}"));
            }
        },
        Err(e) => {
            rec.launch_error
                .get_or_insert(format!("perf-launch wrote no result: {e}"));
        }
    }
    rec.target = target_facts(&std::fs::read(&stdout_path).unwrap_or_default(), workload);

    let attempts: Vec<AttemptFacts> = rec
        .launcher
        .as_ref()
        .and_then(|l| l.attempts.clone())
        .unwrap_or_default();
    if let [only] = attempts.as_slice() {
        let bytes = std::fs::read(Path::new(&only.dir).join("jail.json"));
        if let Some(receipt) = bytes
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        {
            rec.receipt = receipt_facts(&receipt).ok();
        }
    }
    rec.validity = validate(&rec);
    if !rec.validity.valid {
        let err = std::fs::read(&stderr_path).unwrap_or_default();
        let tail = &err[err.len().saturating_sub(2000)..];
        rec.stderr_tail = Some(String::from_utf8_lossy(tail).into_owned());
    }

    // Keep the data directory warm and empty: remove what this launch left
    // once it is settled and cleaned up; otherwise keep it for inspection
    // and give the arm a fresh data directory.
    let cleaned = rec.receipt.as_ref().is_some_and(|r| {
        r.phase == "settled"
            && matches!(r.state_cleanup.as_deref(), Some("complete" | "not_needed"))
    });
    if !attempts.is_empty() {
        if cleaned && attempts.len() == 1 {
            std::fs::remove_dir_all(&attempts[0].dir)
                .map_err(|e| format!("remove {}: {e}", attempts[0].dir))?;
        } else {
            rec.kept_attempt = Some(state.data().display().to_string());
            state.generation += 1;
            state.prepare()?;
        }
    }
    Ok(rec)
}

// --------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    const T0: u64 = 1_000_000_000;

    fn target(start: u64, end: u64) -> TargetFacts {
        TargetFacts {
            lines: 2,
            start_ns: Some(start),
            timens: Some("time:[4026531834]".to_owned()),
            pid: Some(42),
            end_ns: Some(end),
            ok: Some(true),
            maxrss_kib: Some(2000),
            children_maxrss_kib: Some(0),
            summary: None,
        }
    }

    fn launcher(t1: u64) -> LauncherFacts {
        LauncherFacts {
            pid: 42,
            t0_ns: T0,
            t1_ns: t1,
            timens: Some("time:[4026531834]".to_owned()),
            status: ExitFacts {
                exited: true,
                code: Some(0),
                signal: None,
            },
            rusage: RusageFacts {
                maxrss_kib: 9000,
                ..RusageFacts::default()
            },
            ..LauncherFacts::default()
        }
    }

    fn complete_attempt() -> AttemptFacts {
        AttemptFacts {
            id: Some("att_1".to_owned()),
            dir: "/nonexistent/att_1".to_owned(),
            receipt: true,
            trace: TraceFacts {
                state: "complete".to_owned(),
                frames: 7,
                ..TraceFacts::default()
            },
        }
    }

    fn class(status: &str, count: Option<u64>) -> ClassFacts {
        ClassFacts {
            status: status.to_owned(),
            observed_count: count,
            gaps: 0,
            lost: 0,
        }
    }

    fn settled(profile: &str, observe: &str, scope: &str) -> ReceiptFacts {
        let active = observe == "on";
        let mut coverage = BTreeMap::new();
        for c in CLOSED_SET {
            coverage.insert(
                c.to_owned(),
                if active {
                    class("active", Some(2))
                } else {
                    class("unsupported", None)
                },
            );
        }
        coverage.insert("limits".to_owned(), class("active", Some(0)));
        coverage.insert("proxy.net".to_owned(), class("unsupported", None));
        ReceiptFacts {
            attempt_id: "att_1".to_owned(),
            phase: "settled".to_owned(),
            policy_name: Some(profile.to_owned()),
            policy_observe: Some(observe.to_owned()),
            outcome_kind: "exited".to_owned(),
            outcome_code: Some(0),
            integrity: Some("verified".to_owned()),
            tree_empty: Some(true),
            observer_attached: active,
            coverage,
            supervisor_scope: Some(scope.to_owned()),
            state_cleanup: Some("complete".to_owned()),
            ..ReceiptFacts::default()
        }
    }

    /// A valid direct launch: startup `startup` ms, wall `wall` ms.
    fn direct(session: Session, startup_ms: u64, wall_ms: u64) -> LaunchRecord {
        let start = T0 + startup_ms * 1_000_000;
        let t1 = T0 + wall_ms * 1_000_000;
        let mut r = LaunchRecord::new(session, Workload::Fileops, Arm::Direct, 0, false);
        r.launcher = Some(launcher(t1));
        r.target = target(start, t1 - 1_000_000);
        r
    }

    /// A valid jailed launch of `tool` from a plain session.
    fn jailed(observe: Observe, startup_ms: u64, wall_ms: u64) -> LaunchRecord {
        let mut r = direct(Session::Plain, startup_ms, wall_ms);
        r.arm = Arm::Jailed(Profile::Tool, observe);
        r.launcher.as_mut().unwrap().attempts = Some(vec![complete_attempt()]);
        r.receipt = Some(settled("tool", observe.name(), "entered"));
        r
    }

    fn reasons(r: &LaunchRecord) -> Vec<Reason> {
        validate(r).reasons
    }

    // ------------------------------------------------------------ statistics

    #[test]
    fn the_median_is_the_middle_or_the_mean_of_the_two_middles() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[5.0]), Some(5.0));
        assert_eq!(median(&[1.0, 2.0, 9.0]), Some(2.0));
        assert_eq!(median(&[1.0, 2.0, 4.0, 9.0]), Some(3.0));
    }

    #[test]
    fn p95_is_the_nearest_rank() {
        let thirty: Vec<f64> = (1..=30).map(f64::from).collect();
        assert_eq!(p95(&thirty), Some(29.0), "⌈28.5⌉ = 29th of 30");
        let twenty: Vec<f64> = (1..=20).map(f64::from).collect();
        assert_eq!(p95(&twenty), Some(19.0), "⌈19⌉ = 19th of 20");
        let hundred: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(p95(&hundred), Some(95.0));
        assert_eq!(p95(&[7.0]), Some(7.0));
        assert_eq!(p95(&[1.0, 2.0]), Some(2.0), "⌈1.9⌉ = 2nd of 2");
        assert_eq!(p95(&[]), None);
    }

    #[test]
    fn a_distribution_sorts_its_input_and_drops_non_finite_values() {
        let d = dist([3.0, f64::NAN, 1.0, 2.0, f64::INFINITY]).unwrap();
        assert_eq!(
            d,
            Dist {
                n: 3,
                median: 2.0,
                p95: 3.0,
                min: 1.0,
                max: 3.0
            }
        );
        assert_eq!(dist(std::iter::empty()), None);
    }

    #[test]
    fn timings_follow_the_four_readings() {
        let r = direct(Session::Plain, 3, 200);
        let t = timings(&r).unwrap();
        assert_eq!(t.startup, 3_000_000);
        assert_eq!(t.wall, 200_000_000);
        assert_eq!(t.work, 196_000_000);
        assert_eq!(t.teardown, 1_000_000);
        let mut backwards = r.clone();
        backwards.target.start_ns = Some(T0 - 1);
        assert_eq!(timings(&backwards), None);
    }

    // -------------------------------------------------------------- validity

    #[test]
    fn complete_launches_are_valid() {
        assert_eq!(
            validate(&direct(Session::Plain, 1, 150)),
            Validity {
                valid: true,
                reasons: vec![],
                flags: vec![]
            }
        );
        assert!(validate(&jailed(Observe::On, 100, 900)).valid);
        assert!(validate(&jailed(Observe::Off, 100, 300)).valid);
        let mut scope = jailed(Observe::On, 100, 900);
        scope.session = Session::Scope;
        scope.receipt.as_mut().unwrap().supervisor_scope = Some("already_delegated".to_owned());
        assert!(validate(&scope).valid);
    }

    #[test]
    fn a_launch_that_did_not_run_or_report_is_excluded() {
        let mut r = direct(Session::Plain, 1, 150);
        r.launcher = None;
        assert_eq!(reasons(&r), vec![Reason::LaunchFailed]);

        let mut r = direct(Session::Plain, 1, 150);
        r.launch_error = Some("perf-launch exited 2".to_owned());
        assert_eq!(reasons(&r), vec![Reason::LaunchFailed]);

        let mut r = direct(Session::Plain, 1, 150);
        r.launcher.as_mut().unwrap().exec_errno = Some("ENOENT".to_owned());
        assert!(reasons(&r).contains(&Reason::ExecFailed));

        let mut r = direct(Session::Plain, 1, 150);
        r.launcher.as_mut().unwrap().timed_out = true;
        assert_eq!(reasons(&r), vec![Reason::TimedOut]);

        let mut r = direct(Session::Plain, 1, 150);
        r.target.start_ns = None;
        assert_eq!(reasons(&r), vec![Reason::NoStartLine]);

        let mut r = direct(Session::Plain, 1, 150);
        r.target.end_ns = None;
        r.target.ok = None;
        assert_eq!(reasons(&r), vec![Reason::NoEndLine]);

        let mut r = direct(Session::Plain, 1, 150);
        r.target.ok = Some(false);
        assert_eq!(reasons(&r), vec![Reason::WorkloadFailed]);
    }

    #[test]
    fn startup_needs_one_clock_and_ordered_readings() {
        let mut r = direct(Session::Plain, 1, 150);
        r.target.timens = Some("time:[1]".to_owned());
        assert_eq!(reasons(&r), vec![Reason::ClockNamespace]);
        let mut r = direct(Session::Plain, 1, 150);
        r.launcher.as_mut().unwrap().timens = None;
        r.target.timens = None;
        assert_eq!(
            reasons(&r),
            vec![Reason::ClockNamespace],
            "unknown is not equal"
        );
        let mut r = direct(Session::Plain, 1, 150);
        r.target.end_ns = Some(T0 + 151_000_000);
        assert_eq!(reasons(&r), vec![Reason::ClockOrder]);
    }

    #[test]
    fn direct_execution_must_exit_zero() {
        let mut r = direct(Session::Plain, 1, 150);
        r.launcher.as_mut().unwrap().status.code = Some(3);
        assert_eq!(reasons(&r), vec![Reason::DirectExit]);
        let mut r = direct(Session::Plain, 1, 150);
        r.launcher.as_mut().unwrap().status = ExitFacts {
            exited: false,
            code: None,
            signal: Some(9),
        };
        assert_eq!(reasons(&r), vec![Reason::DirectExit]);
    }

    #[test]
    fn a_jailed_launch_needs_one_settled_receipt_of_its_own_arm() {
        let mut r = jailed(Observe::On, 100, 900);
        r.launcher.as_mut().unwrap().attempts = Some(vec![complete_attempt(), complete_attempt()]);
        assert_eq!(reasons(&r), vec![Reason::AttemptCount]);

        let mut r = jailed(Observe::On, 100, 900);
        r.receipt = None;
        assert_eq!(reasons(&r), vec![Reason::NoReceipt]);

        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().phase = "enforced".to_owned();
        assert_eq!(reasons(&r), vec![Reason::NotSettled]);

        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().policy_observe = Some("off".to_owned());
        assert_eq!(reasons(&r), vec![Reason::PolicyMismatch]);

        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().policy_name = Some("agent".to_owned());
        assert_eq!(reasons(&r), vec![Reason::PolicyMismatch]);
    }

    #[test]
    fn the_session_must_be_the_one_measured() {
        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().supervisor_scope = Some("already_delegated".to_owned());
        assert_eq!(reasons(&r), vec![Reason::SessionMismatch]);
        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().supervisor_scope = Some("unavailable".to_owned());
        assert_eq!(reasons(&r), vec![Reason::SessionMismatch]);
        let mut r = jailed(Observe::On, 100, 900);
        r.session = Session::Scope;
        assert_eq!(reasons(&r), vec![Reason::SessionMismatch]);
    }

    #[test]
    fn the_outcome_must_be_exit_zero_and_the_jail_must_agree() {
        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().outcome_code = Some(1);
        assert_eq!(reasons(&r), vec![Reason::Outcome]);

        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().outcome_kind = "signaled".to_owned();
        r.receipt.as_mut().unwrap().outcome_code = None;
        assert_eq!(reasons(&r), vec![Reason::Outcome]);

        let mut r = jailed(Observe::On, 100, 900);
        r.launcher.as_mut().unwrap().status.code = Some(1);
        assert_eq!(reasons(&r), vec![Reason::JailExit]);
    }

    #[test]
    fn the_observe_off_exec_limit_is_flagged_not_hidden_and_only_off() {
        let unconfirmed = |observe: Observe| {
            let mut r = jailed(observe, 100, 300);
            let rc = r.receipt.as_mut().unwrap();
            rc.outcome_kind = "unknown".to_owned();
            rc.outcome_code = None;
            rc.outcome_cause = Some(EXEC_UNCONFIRMED.to_owned());
            r.launcher.as_mut().unwrap().status.code = Some(1);
            r
        };
        let v = validate(&unconfirmed(Observe::Off));
        assert!(v.valid, "{v:?}");
        assert_eq!(v.flags, vec![Flag::ExecUnconfirmed]);

        // With observation on, an unconfirmed exec is a real defect.
        assert!(reasons(&unconfirmed(Observe::On)).contains(&Reason::Outcome));

        // Another unknown cause is not the recorded limit.
        let mut r = unconfirmed(Observe::Off);
        r.receipt.as_mut().unwrap().outcome_cause = Some("something else".to_owned());
        assert_eq!(reasons(&r), vec![Reason::Outcome]);

        // The jail must still end on its own with an ordinary nonzero code.
        for bad in [Some(0), Some(125), None] {
            let mut r = unconfirmed(Observe::Off);
            r.launcher.as_mut().unwrap().status.code = bad;
            r.launcher.as_mut().unwrap().status.exited = bad.is_some();
            assert_eq!(reasons(&r), vec![Reason::JailExit], "{bad:?}");
        }
    }

    #[test]
    fn errors_gaps_and_degradation_exclude() {
        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().errors = vec!["evidence_lost".to_owned()];
        assert_eq!(reasons(&r), vec![Reason::Errors]);

        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().integrity = Some("unverified".to_owned());
        assert_eq!(reasons(&r), vec![Reason::TreeNotVerified]);
        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().tree_empty = Some(false);
        assert_eq!(reasons(&r), vec![Reason::TreeNotVerified]);

        let mut r = jailed(Observe::Off, 100, 300);
        r.receipt
            .as_mut()
            .unwrap()
            .coverage
            .insert("limits".to_owned(), class("degraded", None));
        assert_eq!(reasons(&r), vec![Reason::CoverageDegraded]);

        let mut r = jailed(Observe::On, 100, 900);
        r.receipt
            .as_mut()
            .unwrap()
            .coverage
            .get_mut("fs.write")
            .unwrap()
            .gaps = 1;
        assert_eq!(reasons(&r), vec![Reason::CoverageGaps]);

        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().observer_gaps = 1;
        assert_eq!(reasons(&r), vec![Reason::ObserverGaps]);
    }

    #[test]
    fn observation_on_needs_an_attached_observer_and_the_whole_closed_set() {
        let mut r = jailed(Observe::On, 100, 900);
        r.receipt.as_mut().unwrap().observer_attached = false;
        assert_eq!(reasons(&r), vec![Reason::ObserverDetached]);
        for missing in CLOSED_SET {
            let mut r = jailed(Observe::On, 100, 900);
            r.receipt
                .as_mut()
                .unwrap()
                .coverage
                .insert(missing.to_owned(), class("supported", None));
            assert_eq!(reasons(&r), vec![Reason::ClassNotActive], "{missing}");
            let mut r = jailed(Observe::On, 100, 900);
            r.receipt.as_mut().unwrap().coverage.remove(missing);
            assert_eq!(
                reasons(&r),
                vec![Reason::ClassNotActive],
                "{missing} absent"
            );
        }
        // With observation off the closed set is not asked for.
        assert!(validate(&jailed(Observe::Off, 100, 300)).valid);
    }

    #[test]
    fn a_trace_that_is_not_a_complete_transcript_excludes() {
        let bad = |f: &dyn Fn(&mut TraceFacts)| {
            let mut r = jailed(Observe::On, 100, 900);
            f(&mut r.launcher.as_mut().unwrap().attempts.as_mut().unwrap()[0].trace);
            reasons(&r)
        };
        assert_eq!(
            bad(&|t| t.guard = Some("the trace's last frame is not a note".to_owned())),
            vec![Reason::TraceIncomplete]
        );
        assert_eq!(
            bad(&|t| t.state = "incomplete".to_owned()),
            vec![Reason::TraceIncomplete]
        );
        assert_eq!(
            bad(&|t| t.error = Some("No such file".to_owned())),
            vec![Reason::TraceIncomplete]
        );
        let mut r = jailed(Observe::On, 100, 900);
        r.launcher.as_mut().unwrap().attempts = None;
        assert!(reasons(&r).contains(&Reason::TraceIncomplete));
        assert!(reasons(&r).contains(&Reason::AttemptCount));
    }

    // ---------------------------------------------------------------- summary

    #[test]
    fn an_excluded_launch_is_counted_and_never_averaged() {
        let mut records = vec![
            direct(Session::Plain, 1, 100),
            direct(Session::Plain, 1, 100),
            direct(Session::Plain, 1, 100),
        ];
        let mut outlier = direct(Session::Plain, 1, 100_000);
        outlier.target.ok = Some(false);
        records.push(outlier);
        let mut warm = direct(Session::Plain, 1, 50_000);
        warm.warmup = true;
        records.push(warm);
        let refs: Vec<&LaunchRecord> = records.iter().filter(|r| !r.warmup).collect();
        let cell = summarize_cell((Session::Plain, Workload::Fileops, Arm::Direct), &refs);
        assert_eq!(cell.launched, 4);
        assert_eq!(cell.valid, 3);
        assert_eq!(cell.excluded, 1);
        assert_eq!(cell.excluded_by_reason.get("workload_failed"), Some(&1));
        let wall = cell.wall_ms.unwrap();
        assert_eq!((wall.n, wall.max), (3, 100.0), "the outlier is not in it");

        let summary = summarize(&records, Value::Null, Value::Null);
        assert_eq!(
            summary.warmup_launches, 1,
            "the warm-up is recorded, not summarised"
        );
        assert_eq!(summary.cells.len(), 1);
        assert_eq!(summary.cells[0].launched, 4);
    }

    #[test]
    fn validity_is_recomputed_not_trusted_from_the_record() {
        let mut r = direct(Session::Plain, 1, 100);
        r.target.ok = Some(false);
        r.validity = Validity {
            valid: true,
            reasons: vec![],
            flags: vec![],
        };
        let cell = summarize_cell((Session::Plain, Workload::Fileops, Arm::Direct), &[&r]);
        assert_eq!(cell.valid, 0);
    }

    fn many(f: impl Fn(u64) -> LaunchRecord, n: u64) -> Vec<LaunchRecord> {
        (0..n).map(f).collect()
    }

    #[test]
    fn added_startup_and_overhead_are_against_the_baseline_median() {
        // Direct: startups 1..=30 ms (median 15.5), walls 100 ms.
        let base = many(|i| direct(Session::Plain, i + 1, 100), 30);
        // Off: startups 101..=130 ms, walls 250 ms (+150%).
        let off = many(|i| jailed(Observe::Off, 101 + i, 250), 30);
        let b: Vec<&LaunchRecord> = base.iter().collect();
        let s: Vec<&LaunchRecord> = off.iter().collect();
        let c = compare(
            Session::Plain,
            Workload::Fileops,
            Profile::Tool,
            CompareKind::OffVsDirect,
            (Arm::Jailed(Profile::Tool, Observe::Off), &s),
            (Arm::Direct, &b),
        );
        assert_eq!(c.baseline_startup_median_ms, Some(15.5));
        let added = c.added_startup_ms.as_ref().unwrap();
        assert!((added.median - 100.0).abs() < 1e-9, "{added:?}");
        assert!(
            (added.p95 - (129.0 - 15.5)).abs() < 1e-9,
            "29th of 30: {added:?}"
        );
        let wall = c.wall_overhead_pct.as_ref().unwrap();
        assert!((wall.median - 150.0).abs() < 1e-9, "{wall:?}");
        assert_eq!(c.startup_verdict, Some(Verdict::Pass));
        assert_eq!(c.wall_verdict, Some(Verdict::Fail));
        assert_eq!((c.subject_valid, c.baseline_valid), (30, 30));
    }

    #[test]
    fn verdicts_fail_at_the_budget_and_need_thirty_on_both_sides() {
        let base = many(|_| direct(Session::Plain, 1, 100), 30);
        // 251 ms against a 1 ms median: exactly 250 ms added, which is not
        // under 250; a 400 ms wall is 300% over the 100 ms median.
        let slow = many(|_| jailed(Observe::On, 251, 400), 30);
        let b: Vec<&LaunchRecord> = base.iter().collect();
        let s: Vec<&LaunchRecord> = slow.iter().collect();
        let on = Arm::Jailed(Profile::Tool, Observe::On);
        let c = compare(
            Session::Plain,
            Workload::Fileops,
            Profile::Tool,
            CompareKind::OnVsDirect,
            (on, &s),
            (Arm::Direct, &b),
        );
        assert_eq!(c.added_startup_ms.as_ref().unwrap().p95, 250.0);
        assert_eq!(c.startup_verdict, Some(Verdict::Fail));
        assert_eq!(c.wall_verdict, Some(Verdict::Fail));
        // One valid launch short on either side is not a measurement.
        let c = compare(
            Session::Plain,
            Workload::Fileops,
            Profile::Tool,
            CompareKind::OnVsDirect,
            (on, &s[..29]),
            (Arm::Direct, &b),
        );
        assert_eq!(c.startup_verdict, Some(Verdict::Insufficient));
        assert_eq!(c.wall_verdict, Some(Verdict::Insufficient));
        let c = compare(
            Session::Plain,
            Workload::Fileops,
            Profile::Tool,
            CompareKind::OnVsDirect,
            (on, &s),
            (Arm::Direct, &b[..29]),
        );
        assert_eq!(c.startup_verdict, Some(Verdict::Insufficient));
    }

    #[test]
    fn a_budget_is_strict_and_short_samples_are_insufficient() {
        assert_eq!(verdict(30, 30, Some(249.9), 250.0), Verdict::Pass);
        assert_eq!(verdict(30, 30, Some(250.0), 250.0), Verdict::Fail);
        assert_eq!(verdict(30, 30, Some(19.99), 20.0), Verdict::Pass);
        assert_eq!(verdict(30, 30, Some(20.0), 20.0), Verdict::Fail);
        assert_eq!(verdict(29, 30, Some(1.0), 250.0), Verdict::Insufficient);
        assert_eq!(verdict(30, 29, Some(1.0), 250.0), Verdict::Insufficient);
        assert_eq!(verdict(30, 30, None, 250.0), Verdict::Insufficient);
    }

    #[test]
    fn only_the_fixed_workload_against_direct_has_an_overhead_verdict() {
        let base = many(|_| direct(Session::Plain, 1, 100), 30);
        let off = many(|_| jailed(Observe::Off, 50, 200), 30);
        let on = many(|_| jailed(Observe::On, 60, 900), 30);
        let summary = summarize(
            &[base.clone(), off.clone(), on.clone()].concat(),
            Value::Null,
            Value::Null,
        );
        let find = |kind| {
            summary
                .comparisons
                .iter()
                .find(|c| c.kind == kind)
                .unwrap()
                .clone()
        };
        let off_direct = find(CompareKind::OffVsDirect);
        assert_eq!(off_direct.wall_verdict, Some(Verdict::Fail), "+100%");
        assert_eq!(off_direct.startup_verdict, Some(Verdict::Pass));
        let on_off = find(CompareKind::OnVsOff);
        assert_eq!(on_off.startup_verdict, None);
        assert_eq!(on_off.wall_verdict, None);
        let w = on_off.wall_overhead_pct.unwrap();
        assert!((w.median - 350.0).abs() < 1e-9, "900 over 200: {w:?}");
        assert_eq!(summary.comparisons.len(), 3);

        let mut noop = base.clone();
        for r in &mut noop {
            r.workload = Workload::Noop;
        }
        let mut noop_off = off.clone();
        for r in &mut noop_off {
            r.workload = Workload::Noop;
        }
        let summary = summarize(&[noop, noop_off].concat(), Value::Null, Value::Null);
        let c = &summary.comparisons[0];
        assert_eq!(c.kind, CompareKind::OffVsDirect);
        assert_eq!(
            c.wall_verdict, None,
            "no overhead budget outside the fixed workload"
        );
        assert_eq!(c.startup_verdict, Some(Verdict::Pass));
    }

    #[test]
    fn a_flagged_launch_counts_and_is_shown_as_flagged() {
        let base = many(|_| direct(Session::Plain, 1, 100), 30);
        let off = many(
            |_| {
                let mut r = jailed(Observe::Off, 50, 200);
                let rc = r.receipt.as_mut().unwrap();
                rc.outcome_kind = "unknown".to_owned();
                rc.outcome_code = None;
                rc.outcome_cause = Some(EXEC_UNCONFIRMED.to_owned());
                r.launcher.as_mut().unwrap().status.code = Some(1);
                r
            },
            30,
        );
        let summary = summarize(&[base, off].concat(), Value::Null, Value::Null);
        let c = &summary.comparisons[0];
        assert_eq!(c.kind, CompareKind::OffVsDirect);
        assert_eq!(c.subject_valid, 30);
        assert_eq!(c.subject_flagged.get("exec_unconfirmed"), Some(&30));
        let cell = summary
            .cells
            .iter()
            .find(|c| c.arm == Arm::Jailed(Profile::Tool, Observe::Off))
            .unwrap();
        assert_eq!(cell.flagged.get("exec_unconfirmed"), Some(&30));
        let md = render_markdown(&summary);
        assert!(md.contains("flagged: exec_unconfirmed 30"), "{md}");
    }

    #[test]
    fn a_missing_baseline_yields_no_numbers_and_an_insufficient_verdict() {
        let off = many(|_| jailed(Observe::Off, 50, 200), 30);
        let summary = summarize(&off, Value::Null, Value::Null);
        let c = summary
            .comparisons
            .iter()
            .find(|c| c.kind == CompareKind::OffVsDirect)
            .unwrap();
        assert_eq!(c.baseline_valid, 0);
        assert_eq!(c.added_startup_ms, None);
        assert_eq!(c.startup_verdict, Some(Verdict::Insufficient));
        // Rendering an incomplete summary works and says so.
        let md = render_markdown(&summary);
        assert!(md.contains("Not the §5 measurement"), "{md}");
    }

    #[test]
    fn the_report_states_both_comparisons_and_the_decision() {
        let base = many(|i| direct(Session::Plain, 1 + i % 3, 100), 30);
        let off = many(|_| jailed(Observe::Off, 50, 200), 30);
        let on = many(|_| jailed(Observe::On, 60, 900), 30);
        let summary = summarize(&[base, off, on].concat(), Value::Null, Value::Null);
        let md = render_markdown(&summary);
        for needle in [
            "## Budgets: the jail's own overhead",
            "### Observation on against observation off",
            "### Observation on against direct",
            "tool/off / direct",
            "tool/on / tool/off",
            "fail (100.0%)",
            "pass (",
            "## Definitions",
        ] {
            assert!(md.contains(needle), "missing `{needle}` in\n{md}");
        }
        assert!(
            !md.contains("Not the §5 measurement"),
            "30 valid everywhere"
        );
    }

    // -------------------------------------------------------------- parsing

    #[test]
    fn the_target_lines_are_read_by_op() {
        let stdout = br#"{"op":"perf-start","args":{"mode":"fileops","monotonic_ns":5,"pid":9,"timens":"time:[1]"},"ret":0,"errno":null}
not json
{"op":"fileops","args":{"rounds":3,"start_ns":5,"end_ns":8,"ok":true,"maxrss_kib":1500,"children_maxrss_kib":0},"ret":3,"errno":null}
"#;
        let t = target_facts(stdout, Workload::Fileops);
        assert_eq!(t.lines, 2);
        assert_eq!(t.start_ns, Some(5));
        assert_eq!(t.timens.as_deref(), Some("time:[1]"));
        assert_eq!(t.end_ns, Some(8));
        assert_eq!(t.ok, Some(true));
        assert_eq!(t.maxrss_kib, Some(1500));
        // The spawn-tree summary is not the fileops one.
        let t = target_facts(stdout, Workload::SpawnTree);
        assert_eq!(t.end_ns, None);
    }

    #[test]
    fn the_checked_in_receipt_example_reads_as_facts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/jail-v1/examples");
        let v: Value =
            serde_json::from_slice(&std::fs::read(root.join("receipt-tool.json")).unwrap())
                .unwrap();
        let f = receipt_facts(&v).unwrap();
        assert_eq!(f.phase, "settled");
        assert_eq!(f.policy_name.as_deref(), Some("tool"));
        assert_eq!(f.policy_observe.as_deref(), Some("on"));
        assert_eq!(f.outcome_kind, "exited");
        assert_eq!(f.outcome_code, Some(0));
        assert_eq!(f.integrity.as_deref(), Some("verified"));
        assert_eq!(f.coverage["exec"].status, "active");
        assert_eq!(f.coverage["exec"].observed_count, Some(1));
        assert_eq!(f.coverage["proxy.net"].observed_count, None);
        assert!(f.observer_attached);
        assert_eq!(f.state_cleanup.as_deref(), Some("not_needed"));
        assert!(receipt_facts(&json!({})).is_err());
    }

    #[test]
    fn gaps_and_their_losses_are_summed() {
        let v = json!({
            "phase": "settled",
            "outcome": {"kind": "exited", "code": 0},
            "observer": {"attached": true, "gaps": [{"lost_count": 3}, {"lost_count": null}]},
            "coverage": {"fs.write": {"status": "degraded", "observed_count": null,
                                      "gaps": [{"lost_count": 5}]}},
            "errors": [{"code": "evidence_lost"}],
        });
        let f = receipt_facts(&v).unwrap();
        assert_eq!((f.observer_gaps, f.observer_lost), (2, 3));
        assert_eq!(f.coverage["fs.write"].gaps, 1);
        assert_eq!(f.coverage["fs.write"].lost, 5);
        assert_eq!(f.errors, vec!["evidence_lost".to_owned()]);
    }

    #[test]
    fn a_record_round_trips_through_its_line() {
        let r = jailed(Observe::On, 100, 900);
        let line = serde_json::to_string(&r).unwrap();
        assert!(line.contains("\"arm\":\"tool/on\""), "{line}");
        assert!(line.contains("\"session\":\"plain\""), "{line}");
        let back: LaunchRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(back, r);
        for name in ["direct", "tool/off", "agent/on", "none/off"] {
            let arm = Arm::try_from(name.to_owned()).unwrap();
            assert_eq!(arm.name(), name);
        }
        assert!(Arm::try_from("build/on".to_owned()).is_err());
        assert!(Arm::try_from("tool/maybe".to_owned()).is_err());
    }

    // ---------------------------------------------------------------- runner

    #[test]
    fn every_arm_runs_once_per_round_in_a_rotating_order() {
        let a = arms(&[Profile::Tool, Profile::Agent]);
        assert_eq!(
            a.iter().map(|x| x.name()).collect::<Vec<_>>(),
            ["direct", "tool/off", "tool/on", "agent/off", "agent/on"]
        );
        for round in 0..7 {
            let mut order = round_order(&a, round);
            assert_eq!(order.len(), a.len());
            assert_eq!(order[0], a[round as usize % a.len()]);
            order.sort();
            let mut all = a.clone();
            all.sort();
            assert_eq!(order, all, "round {round} runs every arm once");
        }
        assert!(round_order(&[], 3).is_empty());
    }

    #[test]
    fn the_scope_pass_is_re_executed_with_the_same_parameters() {
        #[derive(Parser)]
        struct Top {
            #[command(subcommand)]
            task: TopTask,
        }
        #[derive(Subcommand)]
        enum TopTask {
            Perf(Cli),
        }
        let args = RunArgs {
            launches: 7,
            warmup: 2,
            sessions: vec![Session::Plain, Session::Scope],
            profiles: vec![Profile::Tool, Profile::None],
            workloads: vec![Workload::Fileops],
            fileops_rounds: 123,
            spawn_count: 45,
            sample_ms: 3,
            deadline_ms: 9999,
            max_load: Some(1.5),
            jail: None,
            fixture: None,
            out: None,
            revision: Some("abc".to_owned()),
            inner: None,
        };
        let argv = inner_argv(&args, Path::new("/o"), Path::new("/j"), Path::new("/f"));
        let parsed =
            Top::try_parse_from(std::iter::once(OsString::from("xtask")).chain(argv)).unwrap();
        let TopTask::Perf(Cli {
            action: Action::Run(inner),
        }) = parsed.task
        else {
            panic!("not a run");
        };
        assert_eq!(
            *inner,
            RunArgs {
                sessions: vec![Session::Scope],
                jail: Some(PathBuf::from("/j")),
                fixture: Some(PathBuf::from("/f")),
                inner: Some(PathBuf::from("/o")),
                ..args
            }
        );
    }

    #[test]
    fn the_user_manager_is_recognised_by_its_unit_component() {
        assert!(under_user_manager(
            "/user.slice/user-1001.slice/user@1001.service/app.slice/run-u1.scope",
            1001
        ));
        assert!(!under_user_manager(
            "/user.slice/user-1001.slice/session-6151.scope",
            1001
        ));
        assert!(!under_user_manager(
            "/user.slice/user-1001.slice/user@10011.service/app.slice/x.scope",
            1001
        ));
        assert!(!under_user_manager("/user@1001.service.d/x", 1001));
    }

    #[test]
    fn the_defaults_are_the_spec_s_workloads() {
        #[derive(Parser)]
        struct Top {
            #[command(flatten)]
            args: RunArgs,
        }
        let t = Top::try_parse_from(["x"]).unwrap();
        assert_eq!(t.args.launches, 30);
        assert_eq!(t.args.warmup, 1);
        assert_eq!(t.args.sessions, vec![Session::Plain, Session::Scope]);
        assert_eq!(
            t.args.profiles,
            vec![Profile::Tool, Profile::Agent, Profile::None]
        );
        assert_eq!(
            t.args.workloads,
            vec![Workload::Noop, Workload::SpawnTree, Workload::Fileops]
        );
        assert_eq!((t.args.fileops_rounds, t.args.spawn_count), (5000, 200));
        let t =
            Top::try_parse_from(["x", "--profiles", "none,tool", "--workloads", "noop"]).unwrap();
        assert_eq!(t.args.profiles, vec![Profile::None, Profile::Tool]);
        assert_eq!(t.args.workloads, vec![Workload::Noop]);
    }
}
