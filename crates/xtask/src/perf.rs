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

const RECORD_SCHEMA: &str = "xtask.perf.launch/2";
const SUMMARY_SCHEMA: &str = "xtask.perf.summary/2";
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
    /// The quiet-host threshold: the run refuses to start above it, and a
    /// verdict needs the 1-minute load average read before every counted
    /// launch at or below it. Required unless --allow-loaded.
    #[arg(long, value_name = "LOAD", required_unless_present = "allow_loaded")]
    pub max_load: Option<f64>,
    /// Measure without a quiet-host threshold: numbers only, no verdict.
    #[arg(long, conflicts_with = "max_load")]
    pub allow_loaded: bool,
    /// Seed of the per-round arm order; default: from the clock. Recorded.
    #[arg(long, value_name = "N")]
    pub seed: Option<u64>,
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

/// SplitMix64: a small, well-mixed generator; enough to order arms, and
/// reproducible from the recorded seed without a dependency.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The arm order of round `round`: a Fisher-Yates permutation drawn from
/// `seed` and the round, so every round runs every arm once, no arm keeps
/// one predecessor, and the recorded seed reproduces the order. (A rotation
/// by one per round, which this replaces, kept each arm's predecessor fixed.)
#[must_use]
pub fn round_order(arms: &[Arm], seed: u64, round: u32) -> Vec<Arm> {
    let mut order = arms.to_vec();
    let mut state = seed ^ u64::from(round).wrapping_mul(0xd1b5_4a32_d192_ed03);
    for i in (1..order.len()).rev() {
        let j = usize::try_from(splitmix64(&mut state) % (i as u64 + 1)).unwrap_or(0);
        order.swap(i, j);
    }
    order
}

/// A per-(session, workload) seed derived from the run's seed, so the two
/// passes and the three workloads do not repeat one order.
#[must_use]
pub fn cell_seed(seed: u64, session: Session, workload: Workload) -> u64 {
    let mut state = seed
        ^ (session as u64).wrapping_mul(0x9e37_79b9)
        ^ (workload as u64).wrapping_mul(0x85eb_ca6b_0000_0001);
    splitmix64(&mut state)
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
    /// The launcher's own cgroup, which a direct target inherits.
    pub cgroup: Option<String>,
    /// `pidfd` (exit seen at once) or `wnohang` (seen within one interval).
    pub waited_via: Option<String>,
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
    /// An event count differs from the workload's exact count, or the trace
    /// and the receipt disagree, with no gap recorded: a silent loss.
    CountMismatch,
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
    /// `/proc/pressure/cpu` `some avg10` (percent) read just before it.
    #[serde(default)]
    pub cpu_pressure_before: Option<f64>,
    /// Growth of `/proc/pressure/cpu` `some total` (µs) across the launch:
    /// time some task on the host waited for a CPU while it ran.
    #[serde(default)]
    pub cpu_stall_us: Option<u64>,
    /// The arm launched immediately before this one in the same pass.
    #[serde(default)]
    pub predecessor: Option<Arm>,
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
            cpu_pressure_before: None,
            cpu_stall_us: None,
            predecessor: None,
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
        // §6.4: a post-launch tool error exits 1, and nothing else is this.
        if !(l.status.exited && l.status.code == Some(1)) {
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
    if !counts_match(rec, observe) {
        reasons.push(Reason::CountMismatch);
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

/// The exact event counts a workload makes under observation, from what the
/// target itself reports it did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected {
    /// Execs: the target itself plus every child it forked.
    pub execs: u64,
    pub created: u64,
    pub renamed: u64,
    pub unlinked: u64,
}

impl Expected {
    #[must_use]
    pub fn of(rec: &LaunchRecord) -> Expected {
        let n = |k: &str| {
            rec.target
                .summary
                .as_ref()
                .and_then(|s| s.get(k))
                .and_then(Value::as_u64)
                .unwrap_or(0)
        };
        match rec.workload {
            Workload::Noop | Workload::SpawnTree => Expected {
                execs: 1 + n("forked"),
                created: 0,
                renamed: 0,
                unlinked: 0,
            },
            Workload::Fileops => Expected {
                execs: 1,
                created: n("created"),
                renamed: n("renamed"),
                unlinked: n("unlinked"),
            },
        }
    }
}

/// Every count is the workload's exact one and the trace agrees with the
/// receipt (measured exact on the reference host in every validation
/// launch). With observation off only the wrapper classes are checked and no
/// audit frame may appear.
#[must_use]
pub fn counts_match(rec: &LaunchRecord, observe: Observe) -> bool {
    let (Some(r), Some(trace)) = (
        rec.receipt.as_ref(),
        rec.launcher
            .as_ref()
            .and_then(|l| l.attempts.as_ref())
            .and_then(|a| a.first())
            .map(|a| &a.trace),
    ) else {
        // Missing facts are excluded by their own reasons.
        return true;
    };
    let class = |k: &str| r.coverage.get(k).and_then(|c| c.observed_count);
    let op = |k: &str| trace.by_operation.get(k).copied().unwrap_or(0);
    let audit = trace.by_source.get("audit").copied().unwrap_or(0);
    // No limit is hit and nothing is proxied by these workloads.
    if class("limits").is_some_and(|c| c != 0) || class("proxy.net").is_some_and(|c| c != 0) {
        return false;
    }
    if observe == Observe::Off {
        return audit == 0;
    }
    if CLOSED_SET
        .iter()
        .any(|k| r.coverage.get(*k).is_none_or(|c| c.status != "active"))
    {
        // An inactive class is excluded as `class_not_active`; its count
        // means nothing.
        return true;
    }
    let e = Expected::of(rec);
    let fs_write = e.created + e.renamed + e.unlinked;
    class("exec") == Some(2 * e.execs)
        && class("fs.write") == Some(fs_write)
        && class("fs.deny") == Some(0)
        && class("net") == Some(0)
        && op("proc.exec") == e.execs
        && op("proc.exit") == e.execs
        && op("fs.create") == e.created
        && op("fs.rename") == e.renamed
        && op("fs.unlink") == e.unlinked
        && audit == 2 * e.execs + fs_write
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
    /// The launcher's reading after the reap minus the target's end reading:
    /// the target's exit, settlement, tree verification, the receipts, the
    /// trace flush and the leaf's removal, for a jailed arm.
    pub teardown: u64,
    /// Everything after the target's entry reading: work + teardown, so that
    /// startup + post-start = wall.
    pub post_start: u64,
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
        post_start: l.t1_ns - start,
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
    pub post_start_ms: Option<Dist>,
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
    /// Fewer than 30 valid launches on one side, any excluded launch on
    /// either side, or a problem with the raw data: no verdict.
    Insufficient,
    /// Enough clean data, but the host was not shown quiet (a counted launch
    /// above --max-load, an unrecorded load, or --allow-loaded): numbers
    /// only, no verdict.
    Loaded,
}

/// What a verdict needs beyond the numbers.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Gate {
    /// The quiet-host threshold; `None` when the run had none
    /// (--allow-loaded, or no parameters): then no verdict.
    pub max_load: Option<f64>,
    /// The raw data passed every integrity check.
    pub integrity_ok: bool,
}

impl Gate {
    #[must_use]
    pub fn from_parameters(parameters: &Value, integrity_ok: bool) -> Gate {
        let allow_loaded = parameters["allow_loaded"].as_bool().unwrap_or(false);
        Gate {
            max_load: if allow_loaded {
                None
            } else {
                parameters["max_load"].as_f64()
            },
            integrity_ok,
        }
    }

    /// Every counted launch had its load recorded, at or below the threshold.
    fn quiet(&self, counted: &[&LaunchRecord]) -> bool {
        self.max_load.is_some_and(|max| {
            counted
                .iter()
                .all(|r| r.load1_before.is_some_and(|l| l <= max))
        })
    }
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
    pub baseline_teardown_median_ms: Option<f64>,
    pub baseline_post_start_median_ms: Option<f64>,
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
    /// Median work-phase overhead under 20%; fixed workload against direct
    /// only. The integrator's current reading of the §5 overhead budget.
    pub work_verdict: Option<Verdict>,
    /// Per subject launch: its teardown minus the baseline's median teardown.
    pub added_teardown_ms: Option<Dist>,
    /// Per subject launch: its post-start time (work + teardown) over the
    /// baseline's median, minus 1.
    pub post_start_overhead_pct: Option<Dist>,
    /// Median post-start overhead under 20%; fixed workload against direct
    /// only. Startup and post-start together cover the whole wall.
    pub post_start_verdict: Option<Verdict>,
    /// The highest 1-minute load read before a counted launch of either arm.
    pub load1_max: Option<f64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Summary {
    pub schema: String,
    pub parameters: Value,
    pub host: Value,
    pub warmup_launches: usize,
    /// The 1-minute load average read before each measured launch.
    pub load1: Option<Dist>,
    /// `/proc/pressure/cpu` `some avg10` (%) before each measured launch.
    pub cpu_pressure: Option<Dist>,
    /// CPU stall on the host (ms) across each measured launch.
    pub cpu_stall_ms: Option<Dist>,
    /// What a verdict needed beyond the numbers.
    pub gate: Gate,
    /// Problems with the raw data; any one blocks every verdict.
    pub integrity: Vec<String>,
    /// Who summarised which raw bytes (filled by `perf summarize`/`run`).
    pub provenance: Value,
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
        post_start_ms: over(&|_, t| Some(ms(t.post_start))),
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

/// A numeric verdict, withheld when the data or the host do not support one:
/// raw-data problems or any excluded launch on either side make it
/// `insufficient` (a verdict over the survivors of an exclusion is not
/// taken); a host not shown quiet makes it `loaded`.
fn gated(core: Verdict, gate: &Gate, excluded: usize, quiet: bool) -> Verdict {
    if !gate.integrity_ok || excluded > 0 || core == Verdict::Insufficient {
        Verdict::Insufficient
    } else if !quiet {
        Verdict::Loaded
    } else {
        core
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
    gate: &Gate,
) -> Comparison {
    let s = valid_timed(subject.1);
    let b = valid_timed(baseline.1);
    let base_median = |f: &dyn Fn(&Timings) -> u64| {
        let mut v: Vec<f64> = b.iter().map(|(_, t)| ms(f(t))).collect();
        v.sort_by(f64::total_cmp);
        median(&v)
    };
    let b_startup = base_median(&|t| t.startup);
    let b_wall = base_median(&|t| t.wall);
    let b_work = base_median(&|t| t.work);
    let b_teardown = base_median(&|t| t.teardown);
    let b_post = base_median(&|t| t.post_start);
    let added = |base: Option<f64>, f: &dyn Fn(&Timings) -> u64| {
        base.and_then(|base| dist(s.iter().map(|(_, t)| ms(f(t)) - base)))
    };
    let ratio = |base: Option<f64>, f: &dyn Fn(&Timings) -> u64| {
        base.filter(|b| *b > 0.0)
            .and_then(|base| dist(s.iter().map(|(_, t)| (ms(f(t)) / base - 1.0) * 100.0)))
    };
    let added_startup = added(b_startup, &|t| t.startup);
    let added_teardown = added(b_teardown, &|t| t.teardown);
    let wall = ratio(b_wall, &|t| t.wall);
    let work = ratio(b_work, &|t| t.work);
    let post = ratio(b_post, &|t| t.post_start);
    let against_direct = baseline.0 == Arm::Direct;
    let fixed = workload == Workload::Fileops;
    let excluded =
        |records: &[&LaunchRecord]| records.iter().filter(|r| !validate(r).valid).count();
    let (s_excluded, b_excluded) = (excluded(subject.1), excluded(baseline.1));
    let counted: Vec<&LaunchRecord> = s.iter().chain(b.iter()).map(|(r, _)| *r).collect();
    let quiet = gate.quiet(&counted);
    let judge = |value: Option<f64>, budget: f64| {
        gated(
            verdict(s.len(), b.len(), value, budget),
            gate,
            s_excluded + b_excluded,
            quiet,
        )
    };
    Comparison {
        session,
        workload,
        profile,
        kind,
        subject: subject.0,
        baseline: baseline.0,
        subject_valid: s.len(),
        subject_excluded: s_excluded,
        subject_flagged: flagged(&s),
        baseline_valid: b.len(),
        baseline_excluded: b_excluded,
        baseline_startup_median_ms: b_startup,
        baseline_wall_median_ms: b_wall,
        baseline_work_median_ms: b_work,
        baseline_teardown_median_ms: b_teardown,
        baseline_post_start_median_ms: b_post,
        startup_verdict: against_direct
            .then(|| judge(added_startup.as_ref().map(|d| d.p95), STARTUP_BUDGET_MS)),
        wall_verdict: (against_direct && fixed)
            .then(|| judge(wall.as_ref().map(|d| d.median), OVERHEAD_BUDGET_PCT)),
        work_verdict: (against_direct && fixed)
            .then(|| judge(work.as_ref().map(|d| d.median), OVERHEAD_BUDGET_PCT)),
        post_start_verdict: (against_direct && fixed)
            .then(|| judge(post.as_ref().map(|d| d.median), OVERHEAD_BUDGET_PCT)),
        added_startup_ms: added_startup,
        wall_overhead_pct: wall,
        work_overhead_pct: work,
        added_teardown_ms: added_teardown,
        post_start_overhead_pct: post,
        load1_max: counted
            .iter()
            .filter_map(|r| r.load1_before)
            .max_by(f64::total_cmp),
    }
}

/// The problems with a set of raw records that make any verdict unsafe:
/// another schema, a launch recorded twice, a cell whose count is not the
/// run's parameters, or a stored validity the current rules no longer give.
#[must_use]
pub fn integrity_problems(records: &[LaunchRecord], parameters: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let foreign = records.iter().filter(|r| r.schema != RECORD_SCHEMA).count();
    if foreign > 0 {
        problems.push(format!(
            "{foreign} record(s) are not `{RECORD_SCHEMA}`; they are left out"
        ));
    }
    let mut seen: BTreeMap<(Session, Workload, Arm, u32, bool), usize> = BTreeMap::new();
    for r in records.iter().filter(|r| r.schema == RECORD_SCHEMA) {
        *seen
            .entry((r.session, r.workload, r.arm, r.round, r.warmup))
            .or_default() += 1;
    }
    let duplicates: Vec<String> = seen
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|((s, w, a, round, warm), n)| {
            format!(
                "{} {} {} {}{round} x{n}",
                s.name(),
                w.name(),
                a.name(),
                if *warm { "warm-up " } else { "" }
            )
        })
        .collect();
    if !duplicates.is_empty() {
        problems.push(format!(
            "{} duplicate launch key(s), recorded more than once (runs mixed in one \
             directory?): {}",
            duplicates.len(),
            duplicates
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if let Some(want) = parameters["launches"].as_u64() {
        let warm = parameters["warmup"].as_u64();
        let names = |k: &str| -> Option<Vec<String>> {
            parameters[k].as_array().map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
        };
        let mut expected: Vec<(String, String, String)> = Vec::new();
        if let (Some(sessions), Some(workloads), Some(profiles)) =
            (names("sessions"), names("workloads"), names("profiles"))
        {
            for s in &sessions {
                for w in &workloads {
                    expected.push((s.clone(), w.clone(), "direct".to_owned()));
                    for p in &profiles {
                        for o in ["off", "on"] {
                            expected.push((s.clone(), w.clone(), format!("{p}/{o}")));
                        }
                    }
                }
            }
        }
        let mut count: BTreeMap<(String, String, String), (u64, u64)> = BTreeMap::new();
        for e in &expected {
            count.insert(e.clone(), (0, 0));
        }
        for ((s, w, a, _, warm_rec), n) in &seen {
            let e = count
                .entry((s.name().to_owned(), w.name().to_owned(), a.name()))
                .or_default();
            if *warm_rec {
                e.1 += *n as u64;
            } else {
                e.0 += *n as u64;
            }
        }
        for ((s, w, a), (measured, warmups)) in count {
            if measured != want {
                problems.push(format!(
                    "{s} {w} {a}: {measured} measured launch(es), expected {want}"
                ));
            }
            if let Some(warm) = warm
                && warmups != warm
            {
                problems.push(format!(
                    "{s} {w} {a}: {warmups} warm-up launch(es), expected {warm}"
                ));
            }
        }
    }
    let drift = records
        .iter()
        .filter(|r| r.validity != Validity::default() && r.validity != validate(r))
        .count();
    if drift > 0 {
        problems.push(format!(
            "{drift} record(s) whose stored validity differs from the one recomputed now \
             (the validity rules changed since the run; re-run instead)"
        ));
    }
    problems
}

/// The whole summary of a set of launch records.
#[must_use]
pub fn summarize(records: &[LaunchRecord], parameters: Value, host: Value) -> Summary {
    let integrity = integrity_problems(records, &parameters);
    let gate = Gate::from_parameters(&parameters, integrity.is_empty());
    let ours: Vec<LaunchRecord> = records
        .iter()
        .filter(|r| r.schema == RECORD_SCHEMA)
        .cloned()
        .collect();
    let cells = measured(&ours);
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
                &gate,
            ));
        }
    }
    let measured_records = || ours.iter().filter(|r| !r.warmup);
    Summary {
        schema: SUMMARY_SCHEMA.to_owned(),
        parameters,
        host,
        warmup_launches: ours.iter().filter(|r| r.warmup).count(),
        load1: dist(measured_records().filter_map(|r| r.load1_before)),
        cpu_pressure: dist(measured_records().filter_map(|r| r.cpu_pressure_before)),
        cpu_stall_ms: dist(
            measured_records().filter_map(|r| r.cpu_stall_us.map(|u| u as f64 / 1000.0)),
        ),
        gate,
        integrity,
        provenance: Value::Null,
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

fn med_p95_max(d: Option<&Dist>) -> String {
    d.map_or_else(
        || "n/a".to_owned(),
        |d| format!("{:.0} / {:.0} / {:.0}", d.median, d.p95, d.max),
    )
}

fn med_range(d: Option<&Dist>) -> String {
    d.map_or_else(
        || "n/a".to_owned(),
        |d| {
            if (d.min - d.max).abs() < f64::EPSILON {
                format!("{:.0}", d.median)
            } else {
                format!("{:.0} ({:.0}–{:.0})", d.median, d.min, d.max)
            }
        },
    )
}

fn verdict_text(v: Option<Verdict>, value: Option<f64>, unit: &str) -> String {
    match v {
        None => "n/a".to_owned(),
        Some(Verdict::Loaded) => format!("loaded (no verdict; {}{unit})", num(value, 1)),
        Some(Verdict::Insufficient) => format!("insufficient ({}{unit})", num(value, 1)),
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
`fork` and again after `wait4` returns. While the command runs it samples \
the launched process's `VmHWM` and, for a jailed arm only, looks up the \
execution leaf from the receipt and reads its `memory.peak`, every sampling \
interval: a small asymmetric cost (`--sample-ms 0` is the control run).
- **Startup.** From that first reading to the target's own first reading at \
entry to its workload mode (after its exec, dynamic loading and argument \
parsing, the same for every arm). The target reports its time namespace and \
the launcher its own; a launch where they differ or are unknown is excluded. \
For a jailed arm startup includes the supervisor's own start, the scope step \
(plain session), the capability probes, preparation, bubblewrap, observer \
attachment and the exec.
- **Work.** The target's end reading minus its entry reading: the workload \
phase alone, where the observer's per-call cost falls.
- **Teardown.** The launcher's reading after `wait4` minus the target's end \
reading: the target's exit and, for a jailed arm, settlement, tree \
verification, the receipts, the trace flush and the leaf's removal.
- **Post-start.** Work + teardown: everything after the target's entry. \
Startup + post-start = wall, so the startup budget and a post-start budget \
together leave no jail time uncounted.
- **Wall.** The launcher's two readings: spawn to the jail's exit.
- **Added (ms).** A launch's startup (or teardown) minus the baseline arm's \
median, same session and workload. Warm: after the discarded warm-up launch \
of every arm.
- **Overhead (%).** A launch's work, post-start or wall time over the \
baseline arm's median, minus one. The median of these is the ratio of \
medians minus one.
- **Median / p95.** The middle value (mean of the two middle values for an \
even count); p95 by nearest rank, the ⌈0.95·n⌉-th smallest value (the 29th of \
30).
- **Peak RSS.** Launched HWM: the launched process's own `VmHWM` (the \
supervisor for a jailed arm), last sample (a lower bound). Reaped tree: \
`wait4`'s `ru_maxrss`, the largest resident set of the launched process and \
anything it reaped. Leaf: the execution leaf's `memory.peak` (cgroup memory \
including page cache), last sample. Target: the target's own `ru_maxrss` at \
its end.
- **Validity.** A launch counts only if the launcher ran and exec'd, the \
target printed both lines and completed its workload, one clock and ordered \
readings, direct execution exited 0; and for a jailed arm: exactly one \
attempt, a settled final receipt of the arm's profile and observation mode, \
the session's scope state (`entered` from a plain session, \
`already_delegated` in a scope), outcome `exited 0` (or, with observation \
off, the recorded exec-confirmation limit with jail exit 1, flagged), no \
receipt error, tree death verified, no degraded class, no coverage or \
observer gap, with observation on an attached observer and every closed-set \
class active, every event count exactly the workload's (execs: 2 × (1 + \
children) in the `exec` class, one `proc.exec` and one `proc.exit` each; \
fileops: one `fs.create`, `fs.rename`, `fs.unlink` per round, their sum in \
`fs.write`; nothing in `fs.deny`, `net`, `limits`, `proxy.net`; the trace's \
audit frames equal to the receipt's closed-set counts; no audit frame with \
observation off), and a trace that is complete and ends on the final \
receipt's note (§13.3). Everything else is excluded, counted by reason, never \
averaged, and its attempt, stdout and stderr are kept under `kept/`.
- **Verdicts.** Against direct execution only. `insufficient`: fewer than 30 \
valid launches on either side, any excluded launch on either side (no verdict \
over survivors), or a raw-data problem. `loaded`: the host was not shown \
quiet (a counted launch of either side above `--max-load` or with no load \
recorded, or `--allow-loaded`). A roll-up passes only if every cell passes.
- **Arm order.** A seeded permutation per round (seed in the parameters); \
each launch records its predecessor.
- **CPU share.** Not equalised: a direct target runs in the harness's own \
cgroup, a jailed one in its execution leaf, and their CPU weights differ \
only under contention, which the quiet-host condition rules out for a \
verdict. The direct target's cgroup is recorded per launch.
- **Sessions.** The plain and scope passes run one after the other, so a \
difference between them is confounded by time; each pass's load is in \
`passes.ndjson`.
";

/// How the verdicts of several cells combine: pass only if all pass.
fn roll_up(verdicts: &[Verdict]) -> (Option<Verdict>, String) {
    if verdicts.is_empty() {
        return (None, "no cell".to_owned());
    }
    let count = |v: Verdict| verdicts.iter().filter(|x| **x == v).count();
    let overall = if count(Verdict::Fail) > 0 {
        Verdict::Fail
    } else if count(Verdict::Insufficient) > 0 {
        Verdict::Insufficient
    } else if count(Verdict::Loaded) > 0 {
        Verdict::Loaded
    } else {
        Verdict::Pass
    };
    (
        Some(overall),
        format!(
            "{} of {} cells pass, {} fail, {} insufficient, {} loaded",
            count(Verdict::Pass),
            verdicts.len(),
            count(Verdict::Fail),
            count(Verdict::Insufficient),
            count(Verdict::Loaded)
        ),
    )
}

/// The Markdown report.
#[must_use]
pub fn render_markdown(summary: &Summary) -> String {
    let mut md = String::new();
    let p = &summary.parameters;
    let _ = writeln!(md, "# `ouro-jail` performance (jail-v1 §5)\n");
    let _ = writeln!(md, "{}\n", host_line(&summary.host));
    if !summary.provenance.is_null() {
        let v = &summary.provenance;
        let _ = writeln!(
            md,
            "Raw data: `{}`, {} records, sha256 `{}`; summarised {} by xtask {} at source \
             revision `{}`.\n",
            v["raw_file"].as_str().unwrap_or("?"),
            v["raw_records"],
            v["raw_sha256"].as_str().unwrap_or("unknown"),
            v["summarized_at"].as_str().unwrap_or("?"),
            v["summarizer"]["xtask_version"].as_str().unwrap_or("?"),
            v["summarizer"]["source_revision"]
                .as_str()
                .unwrap_or("unknown"),
        );
    }
    let _ = writeln!(
        md,
        "Parameters: {} measured launch(es) per arm after {} warm-up launch(es) per arm \
         ({} warm-up records discarded); sessions {}; profiles {}; workloads {}; fileops \
         {} rounds; spawn-tree {} children; sampling every {} ms; arm order seed {}.\n",
        p["launches"],
        p["warmup"],
        summary.warmup_launches,
        p["sessions"],
        p["profiles"],
        p["workloads"],
        p["fileops_rounds"],
        p["spawn_count"],
        p["sample_ms"],
        p["seed"],
    );
    let dist3 = |d: Option<&Dist>, digits: usize| {
        d.map_or_else(
            || "not recorded".to_owned(),
            |d| {
                format!(
                    "{:.digits$} / {:.digits$} / {:.digits$}",
                    d.min, d.median, d.max
                )
            },
        )
    };
    let threshold = match summary.gate.max_load {
        Some(max) => format!(
            "`--max-load {max}`: a verdict needs every counted launch of both sides at or \
             below it"
        ),
        None => "none (`--allow-loaded`, or no parameters): numbers only, no verdict".to_owned(),
    };
    let _ = writeln!(
        md,
        "Host quietness: threshold {threshold}. Before the measured launches the 1-minute \
         load average was {} and `/proc/pressure/cpu` `some avg10` was {} % (min / median / \
         max); across them the host's CPU stall was {} ms. The host has {} CPUs. The \
         1-minute load includes the harness's own recent launches.\n",
        dist3(summary.load1.as_ref(), 2),
        dist3(summary.cpu_pressure.as_ref(), 2),
        dist3(summary.cpu_stall_ms.as_ref(), 1),
        summary.host["cpus"]
            .as_u64()
            .map_or("?".to_owned(), |n| n.to_string()),
    );
    if !summary.integrity.is_empty() {
        let _ = writeln!(md, "## Raw-data problems: every verdict is withheld\n");
        for problem in &summary.integrity {
            let _ = writeln!(md, "- {problem}");
        }
        let _ = writeln!(md);
    }
    let mut why: Vec<String> = Vec::new();
    if !summary.integrity.is_empty() {
        why.push("the raw data has problems".to_owned());
    }
    if summary.cells.iter().any(|c| c.valid < SPEC_MIN_LAUNCHES)
        || summary
            .comparisons
            .iter()
            .any(|c| c.subject_valid < SPEC_MIN_LAUNCHES || c.baseline_valid < SPEC_MIN_LAUNCHES)
    {
        why.push(format!(
            "an arm has fewer than {SPEC_MIN_LAUNCHES} valid launches"
        ));
    }
    if summary.cells.iter().any(|c| c.excluded > 0) {
        why.push("an arm has excluded launches".to_owned());
    }
    let verdicts = || {
        summary.comparisons.iter().flat_map(|c| {
            [
                c.startup_verdict,
                c.work_verdict,
                c.post_start_verdict,
                c.wall_verdict,
            ]
        })
    };
    if verdicts().any(|v| v == Some(Verdict::Loaded)) {
        why.push("the host was not shown quiet".to_owned());
    }
    if !why.is_empty() {
        let _ = writeln!(
            md,
            "**Not the §5 measurement:** {}; the verdicts this touches are withheld and the \
             numbers are provisional.\n",
            why.join("; ")
        );
    }

    let _ = writeln!(
        md,
        "## Verdict roll-up\n\n\
         A budget holds for a profile only if every cell below passes. The overhead budget \
         is read three ways, each its own verdict: **work phase** (the target's own entry to \
         end; the integrator's current reading of §5), **post-start** (work + teardown: \
         everything after entry, so startup + post-start cover the whole run), and \
         **end-to-end wall** (startup included).\n\n\
         | Profile | Comparison | p95 added startup < 250 ms | Work phase < 20% | \
         Post-start < 20% | End-to-end wall < 20% |\n|---|---|---|---|---|---|"
    );
    let profiles: Vec<Profile> = {
        let mut v: Vec<Profile> = summary.comparisons.iter().map(|c| c.profile).collect();
        v.sort();
        v.dedup();
        v
    };
    for profile in profiles {
        for kind in [CompareKind::OffVsDirect, CompareKind::OnVsDirect] {
            let rows: Vec<&Comparison> = summary
                .comparisons
                .iter()
                .filter(|c| c.profile == profile && c.kind == kind)
                .collect();
            let cell = |f: &dyn Fn(&Comparison) -> Option<Verdict>| {
                let (overall, detail) =
                    roll_up(&rows.iter().filter_map(|c| f(c)).collect::<Vec<_>>());
                format!(
                    "{} ({detail})",
                    overall.map_or_else(|| "n/a".to_owned(), |v| enum_name(&v))
                )
            };
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} | {} |",
                profile.name(),
                enum_name(&kind).replace('_', " "),
                cell(&|c| c.startup_verdict),
                cell(&|c| c.work_verdict),
                cell(&|c| c.post_start_verdict),
                cell(&|c| c.wall_verdict),
            );
        }
    }
    let _ = writeln!(md);

    let _ = writeln!(
        md,
        "## `--observe off` against direct: the jail's own overhead (`tool`)\n\n\
         Under the decision of 2026-09-24 the §5 budgets apply to this comparison if \
         observation misses them (next section); otherwise they apply to both. Each cell: \
         median / p95 over the valid launches. `exec_unconfirmed` marks valid launches whose \
         receipt outcome is `unknown` because, with observation off, the target ended before \
         the supervisor confirmed its exec (the jail then exits 1); the target's own lines \
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
        "## `--observe on` against direct: the budgets with observation (`tool`)\n\n\
         The §5 budgets as first written, observation included.\n"
    );
    comparison_table(
        &mut md,
        summary,
        Some(Profile::Tool),
        CompareKind::OnVsDirect,
        true,
    );
    let _ = writeln!(
        md,
        "## Observation cost: `--observe on` against `--observe off` (reported, no budget)\n"
    );
    comparison_table(&mut md, summary, None, CompareKind::OnVsOff, false);
    let _ = writeln!(md, "## Informational profiles\n");
    for profile in [Profile::Agent, Profile::None] {
        for kind in [CompareKind::OffVsDirect, CompareKind::OnVsDirect] {
            let _ = writeln!(
                md,
                "### `{}`, {}\n",
                profile.name(),
                enum_name(&kind).replace('_', " ")
            );
            comparison_table(&mut md, summary, Some(profile), kind, true);
        }
    }

    let _ = writeln!(md, "## Per arm\n");
    let _ = writeln!(
        md,
        "| Session | Workload | Arm | Valid | Excluded (reasons) | Flagged | Startup ms | Work \
         ms | Teardown ms | Post-start ms | Wall ms |\n|---|---|---|---|---|---|---|---|---|---|---|"
    );
    for c in &summary.cells {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {}/{} | {} ({}) | {} | {} | {} | {} | {} | {} |",
            c.session.name(),
            c.workload.name(),
            c.arm.name(),
            c.valid,
            c.launched,
            c.excluded,
            reasons_text(&c.excluded_by_reason),
            reasons_text(&c.flagged),
            pair(c.startup_ms.as_ref(), 1, ""),
            pair(c.work_ms.as_ref(), 1, ""),
            pair(c.teardown_ms.as_ref(), 1, ""),
            pair(c.post_start_ms.as_ref(), 1, ""),
            pair(c.wall_ms.as_ref(), 1, ""),
        );
    }
    let _ = writeln!(
        md,
        "\n### Peak memory (KiB, median / p95 / max over valid launches)\n\n\
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
            med_p95_max(c.launched_hwm_kib.as_ref()),
            med_p95_max(c.reaped_tree_maxrss_kib.as_ref()),
            med_p95_max(c.leaf_peak_kib.as_ref()),
            med_p95_max(c.target_maxrss_kib.as_ref()),
        );
    }
    let _ = writeln!(
        md,
        "\n### Events and losses\n\n\
         Event counts: the receipt's `coverage.<class>.observed_count` over valid launches, \
         median (min–max). Losses: over every measured launch of the arm, valid or not; a \
         count that differs from the workload's exact one excludes the launch \
         (`count_mismatch`).\n\n\
         | Session | Workload | Arm | Excluded | exec | fs.write | fs.deny | net | proxy.net \
         | Trace frames | Observer gaps (lost) | Coverage gaps (lost) | Receipt errors | \
         Incomplete traces | Trace notes (all kinds) |\n\
         |---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
    );
    for c in summary.cells.iter().filter(|c| c.arm != Arm::Direct) {
        let count = |k: &str| med_range(c.coverage_counts.get(k));
        let l = &c.losses;
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} ({}) | {} ({}) | {} | {} | \
             {} |",
            c.session.name(),
            c.workload.name(),
            c.arm.name(),
            c.excluded,
            count("exec"),
            count("fs.write"),
            count("fs.deny"),
            count("net"),
            count("proxy.net"),
            med_range(c.trace_frames.as_ref()),
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
         Startup: p95 added against direct. Overheads: median against direct, work phase / \
         post-start / end-to-end wall, each with its verdict. Peak RSS: supervisor sampled \
         HWM median / p95 (KiB). Events: median trace frames. Losses: observer + coverage \
         gaps, receipt errors, incomplete traces and excluded launches, over all launches.\n"
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
            "{} session:\n\n| Workload | Observe | Valid (excl.) | Startup p95 added | Work \
             phase | Post-start | End-to-end wall | Peak RSS | Event count | Losses (gaps / \
             errors / incomplete / excluded) |\n|---|---|---|---|---|---|---|---|---|---|",
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
            let median = |d: &Option<Dist>| d.as_ref().map(|d| d.median);
            let _ = writeln!(
                md,
                "| {} | {} | {} ({}) | {} | {} | {} | {} | {} | {} | {} |",
                c.workload.name(),
                observe,
                c.subject_valid,
                c.subject_excluded,
                verdict_text(
                    c.startup_verdict,
                    c.added_startup_ms.as_ref().map(|d| d.p95),
                    " ms"
                ),
                verdict_text(c.work_verdict, median(&c.work_overhead_pct), "%")
                    .replace("n/a", &format!("{}%", num(median(&c.work_overhead_pct), 1))),
                verdict_text(
                    c.post_start_verdict,
                    median(&c.post_start_overhead_pct),
                    "%"
                )
                .replace(
                    "n/a",
                    &format!("{}%", num(median(&c.post_start_overhead_pct), 1))
                ),
                verdict_text(c.wall_verdict, median(&c.wall_overhead_pct), "%")
                    .replace("n/a", &format!("{}%", num(median(&c.wall_overhead_pct), 1))),
                cell.and_then(|x| x.launched_hwm_kib.as_ref()).map_or_else(
                    || "n/a".to_owned(),
                    |d| format!("{:.0} / {:.0}", d.median, d.p95)
                ),
                num(
                    cell.and_then(|x| x.trace_frames.as_ref()).map(|d| d.median),
                    0
                ),
                cell.map_or_else(
                    || "n/a".to_owned(),
                    |x| format!(
                        "{} / {} / {} / {}",
                        x.losses.observer_gaps + x.losses.coverage_gaps,
                        x.losses.receipt_errors,
                        x.losses.incomplete_traces,
                        x.excluded
                    )
                ),
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
         (excl.) baseline | Max load | Baseline median startup / work / teardown / wall ms | \
         Added startup ms | Added teardown ms | Work overhead % | Post-start overhead % | Wall \
         overhead % |"
    );
    if verdicts {
        let _ = write!(
            md,
            " p95 added startup < 250 ms | Work phase < 20% (integrator's reading) | Post-start \
             (work + teardown) < 20% | End-to-end wall < 20% |"
        );
    }
    let _ = writeln!(md);
    let cols = if verdicts { 17 } else { 13 };
    let _ = writeln!(md, "|{}", "---|".repeat(cols));
    for c in rows {
        let _ = write!(
            md,
            "| {} | {} | {} | {} / {} | {} ({}) | {} ({}) | {} | {} / {} / {} / {} | {} | {} | {} \
             | {} | {} |",
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
            num(c.load1_max, 2),
            num(c.baseline_startup_median_ms, 1),
            num(c.baseline_work_median_ms, 1),
            num(c.baseline_teardown_median_ms, 1),
            num(c.baseline_wall_median_ms, 1),
            pair(c.added_startup_ms.as_ref(), 1, ""),
            pair(c.added_teardown_ms.as_ref(), 1, ""),
            pair(c.work_overhead_pct.as_ref(), 1, ""),
            pair(c.post_start_overhead_pct.as_ref(), 1, ""),
            pair(c.wall_overhead_pct.as_ref(), 1, ""),
        );
        if verdicts {
            let median = |d: &Option<Dist>| d.as_ref().map(|d| d.median);
            let _ = write!(
                md,
                " {} | {} | {} | {} |",
                verdict_text(
                    c.startup_verdict,
                    c.added_startup_ms.as_ref().map(|d| d.p95),
                    " ms"
                ),
                verdict_text(c.work_verdict, median(&c.work_overhead_pct), "%"),
                verdict_text(
                    c.post_start_verdict,
                    median(&c.post_start_overhead_pct),
                    "%"
                ),
                verdict_text(c.wall_verdict, median(&c.wall_overhead_pct), "%"),
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
        Action::Summarize { dir } => write_summary(&dir).and_then(|(md, problems)| {
            println!("{md}");
            integrity_result(&problems)
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
    /// The arm-order seed, given or drawn from the clock; recorded.
    seed: u64,
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
    if args.max_load.is_none() && !args.allow_loaded {
        return Err(
            "--max-load is required (or --allow-loaded, which gives no verdict)".to_owned(),
        );
    }
    let seed = args.seed.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64)
    });
    Ok(Plan {
        args: args.clone(),
        out,
        jail,
        fixture,
        seed,
    })
}

/// `run` writes a new directory: it never appends to an earlier run's raw
/// file, which would mix binaries, hosts and parameters under one summary.
/// Only the internal scope pass appends, to the directory its own outer run
/// just created.
///
/// # Errors
/// When `out` exists and is not an empty directory, outside the scope pass.
pub fn check_out_dir(out: &Path, inner: bool) -> Result<(), String> {
    if inner || !out.exists() {
        return Ok(());
    }
    let mut entries = std::fs::read_dir(out).map_err(|e| format!("{}: {e}", out.display()))?;
    if entries.next().is_some() {
        return Err(format!(
            "{} is not empty: refusing to append to an earlier run; choose a new --out",
            out.display()
        ));
    }
    Ok(())
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
    if args.allow_loaded {
        argv.push("--allow-loaded".into());
    }
    if let Some(seed) = args.seed {
        argv.push("--seed".into());
        argv.push(seed.to_string().into());
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
        "allow_loaded": a.allow_loaded,
        "seed": plan.seed,
        "arm_order": "a seeded Fisher-Yates permutation per round (SplitMix64 of seed, session, workload, round)",
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
    let mut plan = resolve(&args)?;
    // The scope pass must use the outer run's seed.
    plan.args.seed = Some(plan.seed);
    check_out_dir(&plan.out, args.inner.is_some())?;
    if args.inner.is_none()
        && let (Some(max), Some(now)) = (plan.args.max_load, load1())
        && now > max
    {
        return Err(format!(
            "the 1-minute load average is {now}, above --max-load {max}: the host is not \
             quiet; nothing was started"
        ));
    }
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
            seed: plan.seed,
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
    let (md, problems) = write_summary(&plan.out)?;
    println!("{md}");
    eprintln!(
        "xtask perf: summary in {}",
        plan.out.join("summary.md").display()
    );
    integrity_result(&problems)
}

fn integrity_result(problems: &[String]) -> Result<(), String> {
    if problems.is_empty() {
        return Ok(());
    }
    Err(format!(
        "the raw data has {} problem(s), so no verdict was taken: {}",
        problems.len(),
        problems.join(" | ")
    ))
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
/// `summary.md`. Returns the Markdown and the raw data's problems.
fn write_summary(dir: &Path) -> Result<(String, Vec<String>), String> {
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
    let mut summary = summarize(
        &records,
        read_json(&dir.join(PARAMETERS_FILE)),
        read_json(&dir.join(HOST_FILE)),
    );
    summary.provenance = json!({
        "raw_file": RAW_FILE,
        "raw_bytes": raw.len(),
        "raw_records": records.len(),
        "raw_sha256": sha256(&dir.join(RAW_FILE)),
        "summarized_at": crate::stamp::rfc3339_from_unix(crate::stamp::unix_now()),
        "summarizer": {
            "xtask_version": env!("CARGO_PKG_VERSION"),
            "record_schema": RECORD_SCHEMA,
            "source_revision": command_text("git", &["rev-parse", "HEAD"])
                .map(|t| t.trim().to_owned())
                .filter(|t| t.len() == 40),
        },
    });
    let v = serde_json::to_value(&summary).map_err(|e| e.to_string())?;
    write_json(&dir.join("summary.json"), &v)?;
    let md = render_markdown(&summary);
    std::fs::write(dir.join("summary.md"), &md)
        .map_err(|e| format!("{}: {e}", dir.join("summary.md").display()))?;
    Ok((md, summary.integrity))
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
    let p = path.to_str()?;
    let text =
        command_text("sha256sum", &[p]).or_else(|| command_text("shasum", &["-a", "256", p]))?;
    let hex = text.split_whitespace().next()?;
    (hex.len() == 64).then(|| hex.to_owned())
}

/// `/proc/pressure/cpu`'s `some` line: (avg10 in percent, total in µs).
#[must_use]
pub fn parse_cpu_pressure(text: &str) -> Option<(f64, u64)> {
    let line = text.lines().find(|l| l.starts_with("some "))?;
    let field = |k: &str| {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(k))
            .map(str::to_owned)
    };
    Some((
        field("avg10=")?.parse().ok()?,
        field("total=")?.parse().ok()?,
    ))
}

fn cpu_pressure() -> Option<(f64, u64)> {
    parse_cpu_pressure(&std::fs::read_to_string("/proc/pressure/cpu").ok()?)
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
    // No load refusal here: a pass refused after another pass ran would leave
    // a half run behind. The outer run refuses before anything starts, and a
    // verdict needs every counted launch at or below --max-load.
    let cgroup = check_session(session)?;
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
        let seed = cell_seed(plan.seed, session, *workload);
        let mut previous: Option<Arm> = None;
        for round in 0..total {
            let warmup = round < plan.args.warmup;
            let index = if warmup {
                round
            } else {
                round - plan.args.warmup
            };
            for arm in round_order(&arm_list, seed, round) {
                let st = states.get_mut(&arm).ok_or("an arm without state")?;
                let mut rec = launch(
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
                rec.predecessor = previous;
                previous = Some(arm);
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
    let load = rec
        .load1_before
        .map_or_else(|| "load ?".to_owned(), |l| format!("load {l:.2}"));
    match timings(rec) {
        Some(t) if rec.validity.valid => eprintln!(
            "{tag} startup {:.1} ms wall {:.1} ms work {:.1} ms teardown {:.1} ms {load}{}",
            ms(t.startup),
            ms(t.wall),
            ms(t.work),
            ms(t.teardown),
            if rec.validity.flags.is_empty() {
                String::new()
            } else {
                format!(" flags {:?}", rec.validity.flags)
            }
        ),
        _ => eprintln!("{tag} EXCLUDED {:?} {load}", rec.validity.reasons),
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
    let pressure_before = cpu_pressure();
    rec.cpu_pressure_before = pressure_before.map(|(avg10, _)| avg10);
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
    let status = cmd.status();
    if let (Some((_, before)), Some((_, after))) = (pressure_before, cpu_pressure()) {
        rec.cpu_stall_us = Some(after.saturating_sub(before));
    }
    match status {
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

    // Keep the data directory warm and empty: remove what a valid launch
    // left once it is settled and cleaned up. An excluded launch keeps its
    // attempt (receipt, trace, state) where it is, so `gc` still finds it
    // and the exclusion can be audited; the arm moves to a fresh data
    // directory. Its stdout and stderr are kept beside the raw file.
    if !rec.validity.valid {
        let kept = plan.out.join("kept").join(format!(
            "{}-{}-{}-{}{}",
            session.name(),
            workload.name(),
            arm.dir_name(),
            if warmup { "warmup-" } else { "" },
            round
        ));
        std::fs::create_dir_all(&kept).map_err(|e| format!("{}: {e}", kept.display()))?;
        let _ = std::fs::copy(&stdout_path, kept.join("stdout"));
        let _ = std::fs::copy(&stderr_path, kept.join("stderr"));
        let _ = std::fs::copy(&result_path, kept.join("perf-launch.json"));
    }
    if !attempts.is_empty() {
        if keep_attempt(&rec) || attempts.len() != 1 {
            rec.kept_attempt = Some(state.data().display().to_string());
            state.generation += 1;
            state.prepare()?;
        } else {
            std::fs::remove_dir_all(&attempts[0].dir)
                .map_err(|e| format!("remove {}: {e}", attempts[0].dir))?;
        }
    }
    Ok(rec)
}

/// Whether a launch's attempt directory must be kept: always for an
/// excluded launch (its receipt and trace are the evidence of why), and for
/// any attempt not settled and cleaned up.
#[must_use]
pub fn keep_attempt(rec: &LaunchRecord) -> bool {
    let cleaned = rec.receipt.as_ref().is_some_and(|r| {
        r.phase == "settled"
            && matches!(r.state_cleanup.as_deref(), Some("complete" | "not_needed"))
    });
    !validate(rec).valid || !cleaned
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
            // What the fixed workload reports after 5,000 clean rounds.
            summary: Some(json!({"rounds": 5000, "created": 5000, "renamed": 5000,
                                 "unlinked": 5000, "ok": true})),
        }
    }

    /// The parameters of a run with a quiet-host threshold of 1.0; every
    /// helper record was taken at load 0.5.
    fn quiet() -> Value {
        json!({ "max_load": 1.0 })
    }

    fn test_gate() -> Gate {
        Gate {
            max_load: Some(1.0),
            integrity_ok: true,
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

    /// The trace a clean fileops launch leaves: exact counts, as measured.
    fn fileops_trace(observe: Observe) -> TraceFacts {
        let mut t = TraceFacts {
            state: "complete".to_owned(),
            frames: 5,
            ..TraceFacts::default()
        };
        t.by_source.insert("wrapper".to_owned(), 5);
        t.by_operation.insert("jail.receipt".to_owned(), 3);
        t.by_operation.insert("note".to_owned(), 2);
        if observe == Observe::On {
            t.frames += 15_002;
            t.by_source.insert("audit".to_owned(), 15_002);
            for op in ["fs.create", "fs.rename", "fs.unlink"] {
                t.by_operation.insert(op.to_owned(), 5000);
            }
            t.by_operation.insert("proc.exec".to_owned(), 1);
            t.by_operation.insert("proc.exit".to_owned(), 1);
        }
        t
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
        for (c, count) in [
            ("exec", 2),
            ("fs.write", 15_000),
            ("fs.deny", 0),
            ("net", 0),
        ] {
            coverage.insert(
                c.to_owned(),
                if active {
                    class("active", Some(count))
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
        r.load1_before = Some(0.5);
        r
    }

    /// A valid jailed launch of `tool` from a plain session.
    fn jailed(observe: Observe, startup_ms: u64, wall_ms: u64) -> LaunchRecord {
        let mut r = direct(Session::Plain, startup_ms, wall_ms);
        r.arm = Arm::Jailed(Profile::Tool, observe);
        let mut attempt = complete_attempt();
        attempt.trace = fileops_trace(observe);
        r.launcher.as_mut().unwrap().attempts = Some(vec![attempt]);
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
        let one = r.launcher.as_ref().unwrap().attempts.as_ref().unwrap()[0].clone();
        r.launcher.as_mut().unwrap().attempts = Some(vec![one.clone(), one]);
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

        for (i, (r, load)) in records
            .iter_mut()
            .zip([0.5, 2.5, 1.0, 1.0, 9.0])
            .enumerate()
        {
            r.round = u32::try_from(i).unwrap();
            r.load1_before = Some(load);
        }
        let summary = summarize(&records, Value::Null, Value::Null);
        assert_eq!(
            summary.warmup_launches, 1,
            "the warm-up is recorded, not summarised"
        );
        let load = summary.load1.as_ref().unwrap();
        assert_eq!(
            (load.n, load.min, load.max),
            (4, 0.5, 2.5),
            "warm-up load excluded"
        );
        assert!(render_markdown(&summary).contains("0.50 / 1.00 / 2.50"));
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

    /// N launches of one arm, rounds 0..N, as a run records them.
    fn many(f: impl Fn(u64) -> LaunchRecord, n: u64) -> Vec<LaunchRecord> {
        (0..n)
            .map(|i| {
                let mut r = f(i);
                r.round = u32::try_from(i).unwrap();
                r
            })
            .collect()
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
            &test_gate(),
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
            &test_gate(),
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
            &test_gate(),
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
            &test_gate(),
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
            quiet(),
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
        let summary = summarize(&[noop, noop_off].concat(), quiet(), Value::Null);
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
        let summary = summarize(&[base, off, on].concat(), quiet(), Value::Null);
        let md = render_markdown(&summary);
        for needle in [
            "## Verdict roll-up",
            "## `--observe off` against direct: the jail's own overhead (`tool`)",
            "## `--observe on` against direct: the budgets with observation (`tool`)",
            "## Observation cost: `--observe on` against `--observe off`",
            "tool/off / direct",
            "tool/on / tool/off",
            "fail (100.0%)",
            "pass (",
            "Work phase < 20% (integrator's reading)",
            "Post-start (work + teardown) < 20%",
            "End-to-end wall < 20%",
            "`--max-load 1`",
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
    fn every_arm_runs_once_per_round_in_a_seeded_order() {
        let a = arms(&[Profile::Tool, Profile::Agent]);
        assert_eq!(
            a.iter().map(|x| x.name()).collect::<Vec<_>>(),
            ["direct", "tool/off", "tool/on", "agent/off", "agent/on"]
        );
        let mut firsts = std::collections::BTreeSet::new();
        for round in 0..20 {
            let mut order = round_order(&a, 42, round);
            firsts.insert(order[0]);
            order.sort();
            let mut all = a.clone();
            all.sort();
            assert_eq!(order, all, "round {round} runs every arm once");
        }
        assert!(firsts.len() > 2, "the first arm varies: {firsts:?}");
        assert!(round_order(&[], 1, 3).is_empty());
        assert_ne!(
            cell_seed(7, Session::Plain, Workload::Noop),
            cell_seed(7, Session::Scope, Workload::Noop)
        );
        assert_ne!(
            cell_seed(7, Session::Plain, Workload::Noop),
            cell_seed(7, Session::Plain, Workload::Fileops)
        );
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
            allow_loaded: false,
            seed: Some(9),
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
    fn cpu_pressure_is_read_from_the_some_line() {
        let text = "some avg10=1.25 avg60=0.50 avg300=0.10 total=123456\n\
                    full avg10=0.00 avg60=0.00 avg300=0.00 total=99\n";
        assert_eq!(parse_cpu_pressure(text), Some((1.25, 123_456)));
        assert_eq!(parse_cpu_pressure("full avg10=0.00 total=1\n"), None);
        assert_eq!(parse_cpu_pressure("some avg10=x total=1\n"), None);
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
        assert!(
            Top::try_parse_from(["x"]).is_err(),
            "a quiet-host threshold or --allow-loaded is required"
        );
        assert!(Top::try_parse_from(["x", "--max-load", "1", "--allow-loaded"]).is_err());
        assert!(Top::try_parse_from(["x", "--allow-loaded"]).is_ok());
        let t = Top::try_parse_from(["x", "--max-load", "2"]).unwrap();
        assert_eq!(t.args.max_load, Some(2.0));
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
        let t = Top::try_parse_from([
            "x",
            "--allow-loaded",
            "--profiles",
            "none,tool",
            "--workloads",
            "noop",
        ])
        .unwrap();
        assert_eq!(t.args.profiles, vec![Profile::None, Profile::Tool]);
        assert_eq!(t.args.workloads, vec![Workload::Noop]);
    }

    // ------------------------------------------------ J5-E adversarial review
    // The review of b8d4f5a0 (scratchpad j5/rev-E) shipped these as passing
    // tests, each pinning a defect. They now assert the fixed behaviour.
    mod review_e {
        use super::*;

        fn off_vs_direct(summary: &Summary, w: Workload) -> &Comparison {
            summary
                .comparisons
                .iter()
                .find(|c| {
                    c.kind == CompareKind::OffVsDirect
                        && c.workload == w
                        && c.profile == Profile::Tool
                })
                .unwrap()
        }

        fn fileops_pair(n: u64) -> Vec<LaunchRecord> {
            let base = many(|_| direct(Session::Plain, 2, 200), n);
            let off = many(|_| jailed(Observe::Off, 100, 330), n);
            let on = many(|_| jailed(Observe::On, 100, 330), n);
            [base, off, on].concat()
        }

        /// F4: the arm order is a seeded permutation per round, so no arm
        /// keeps one predecessor; the same seed gives the same order.
        #[test]
        fn a_seeded_order_varies_each_arms_predecessor() {
            let arm_list = arms(&[Profile::Tool, Profile::Agent, Profile::None]);
            let sequence = |seed: u64| {
                let mut seq: Vec<(Arm, bool)> = Vec::new();
                for round in 0..31 {
                    let order = round_order(&arm_list, seed, round);
                    let mut sorted = order.clone();
                    sorted.sort();
                    let mut all = arm_list.clone();
                    all.sort();
                    assert_eq!(sorted, all, "round {round} is a permutation");
                    seq.extend(order.into_iter().map(|a| (a, round < 1)));
                }
                seq
            };
            let seq = sequence(0x5eed);
            assert_eq!(seq, sequence(0x5eed), "the seed fixes the order");
            assert_ne!(seq, sequence(0x5eee), "another seed, another order");
            let mut pred: BTreeMap<(String, String), usize> = BTreeMap::new();
            for w in seq.windows(2) {
                if !w[1].1 {
                    *pred.entry((w[1].0.name(), w[0].0.name())).or_default() += 1;
                }
            }
            let worst = pred.values().max().copied().unwrap_or(0);
            assert!(worst <= 12, "one predecessor {worst} of 30 times: {pred:?}");
            let get = |a: &str, p: &str| pred.get(&(a.to_owned(), p.to_owned())).copied();
            assert!(get("direct", "none/on").unwrap_or(0) < 26, "{pred:?}");
            assert!(get("tool/off", "direct").unwrap_or(0) < 25, "{pred:?}");
        }

        /// F1: teardown after the workload's last reading is in a verdict:
        /// the post-start figure (work + teardown) against direct's.
        #[test]
        fn teardown_is_in_the_post_start_figure() {
            // Direct: start 2 ms, work 200 ms, teardown 0 ms.
            let mut recs = many(|_| direct(Session::Plain, 2, 202), 30);
            for r in &mut recs {
                r.target.end_ns = Some(T0 + 202_000_000);
            }
            // tool/off: start 100 ms, work 210 ms (+5%), teardown 40 ms.
            recs.extend(many(
                |_| {
                    let mut r = jailed(Observe::Off, 100, 350);
                    r.target.end_ns = Some(T0 + 310_000_000);
                    r
                },
                30,
            ));
            let s = summarize(&recs, quiet(), Value::Null);
            let c = off_vs_direct(&s, Workload::Fileops);
            assert_eq!(c.startup_verdict, Some(Verdict::Pass));
            assert_eq!(c.work_verdict, Some(Verdict::Pass));
            let post = c.post_start_overhead_pct.as_ref().unwrap();
            assert!((post.median - 25.0).abs() < 1e-9, "{post:?}");
            assert_eq!(c.post_start_verdict, Some(Verdict::Fail));
            let teardown = c.added_teardown_ms.as_ref().unwrap();
            assert!((teardown.median - 40.0).abs() < 1e-9, "{teardown:?}");
            let md = render_markdown(&s);
            assert!(md.contains("post-start"), "{md}");
            assert!(md.contains("work phase"), "{md}");
        }

        /// F5: a verdict needs every counted launch at or below --max-load.
        #[test]
        fn a_verdict_needs_every_counted_launch_on_a_quiet_host() {
            let pair = |n: u64| {
                let base = many(|_| direct(Session::Plain, 2, 200), n);
                let off = many(|_| jailed(Observe::Off, 100, 330), n);
                [base, off].concat()
            };
            let verdict_of = |recs: &[LaunchRecord], params: Value| {
                off_vs_direct(&summarize(recs, params, Value::Null), Workload::Fileops)
                    .startup_verdict
            };
            let recs = pair(30);
            assert_eq!(verdict_of(&recs, quiet()), Some(Verdict::Pass));
            let mut one_loud = recs.clone();
            one_loud[3].load1_before = Some(1.5);
            assert_eq!(verdict_of(&one_loud, quiet()), Some(Verdict::Loaded));
            let mut unknown = recs.clone();
            unknown[40].load1_before = None;
            assert_eq!(verdict_of(&unknown, quiet()), Some(Verdict::Loaded));
            assert_eq!(
                verdict_of(&recs, json!({"allow_loaded": true})),
                Some(Verdict::Loaded),
                "--allow-loaded gives numbers, never a verdict"
            );
            assert_eq!(verdict_of(&recs, Value::Null), Some(Verdict::Loaded));
            let md = render_markdown(&summarize(&one_loud, quiet(), Value::Null));
            assert!(md.contains("loaded (no verdict"), "{md}");
        }

        /// F6: an excluded launch keeps its attempt directory.
        #[test]
        fn an_excluded_launch_keeps_its_attempt() {
            let valid = jailed(Observe::On, 100, 900);
            assert!(
                !keep_attempt(&valid),
                "a valid, cleaned-up attempt is removed"
            );
            let mut bad = valid.clone();
            bad.receipt.as_mut().unwrap().errors = vec!["evidence_lost".to_owned()];
            assert!(keep_attempt(&bad), "an excluded launch keeps its evidence");
            let mut pending = valid.clone();
            pending.receipt.as_mut().unwrap().state_cleanup = Some("pending".to_owned());
            assert!(keep_attempt(&pending));
            let mut none = valid;
            none.receipt = None;
            assert!(keep_attempt(&none));
        }

        /// F2: `run` never appends to an existing run directory.
        #[test]
        fn a_run_refuses_a_non_empty_out() {
            let dir = std::env::temp_dir().join(format!(
                "xtask-perf-out-{}-{}",
                std::process::id(),
                crate::stamp::unix_now()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            assert!(check_out_dir(&dir, false).is_ok(), "absent is fine");
            std::fs::create_dir_all(&dir).unwrap();
            assert!(check_out_dir(&dir, false).is_ok(), "empty is fine");
            std::fs::write(dir.join(RAW_FILE), b"{}\n").unwrap();
            let e = check_out_dir(&dir, false).unwrap_err();
            assert!(e.contains("not empty"), "{e}");
            assert!(
                check_out_dir(&dir, true).is_ok(),
                "the scope pass appends by design"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }

        /// F3: every count is exact for the workload and agrees with the trace.
        #[test]
        fn counts_must_match_the_workload_and_the_trace() {
            assert!(validate(&jailed(Observe::On, 100, 900)).valid);
            let bump = |f: &dyn Fn(&mut LaunchRecord)| {
                let mut r = jailed(Observe::On, 100, 900);
                f(&mut r);
                validate(&r).reasons
            };
            for class in ["exec", "fs.write", "fs.deny", "net", "limits"] {
                let reasons = bump(&|r| {
                    let c = r.receipt.as_mut().unwrap().coverage.get_mut(class).unwrap();
                    c.observed_count = Some(c.observed_count.unwrap() + 1);
                });
                assert_eq!(reasons, vec![Reason::CountMismatch], "{class}");
            }
            for op in ["fs.create", "proc.exec", "proc.exit"] {
                let reasons = bump(&|r| {
                    let t = &mut r.launcher.as_mut().unwrap().attempts.as_mut().unwrap()[0].trace;
                    *t.by_operation.get_mut(op).unwrap() -= 1;
                });
                assert_eq!(reasons, vec![Reason::CountMismatch], "trace {op}");
            }
            let reasons = bump(&|r| {
                let t = &mut r.launcher.as_mut().unwrap().attempts.as_mut().unwrap()[0].trace;
                *t.by_source.get_mut("audit").unwrap() += 1;
            });
            assert_eq!(reasons, vec![Reason::CountMismatch], "audit frames");
            // Observation off: no audit frame may appear.
            let mut off = jailed(Observe::Off, 100, 300);
            assert!(validate(&off).valid);
            off.launcher.as_mut().unwrap().attempts.as_mut().unwrap()[0]
                .trace
                .by_source
                .insert("audit".to_owned(), 1);
            assert_eq!(validate(&off).reasons, vec![Reason::CountMismatch]);
        }

        /// F2: duplicates, a foreign schema, a count off the parameters and a
        /// changed validity rule are named problems that block every verdict.
        #[test]
        fn the_raw_file_is_checked_before_any_verdict() {
            let five = fileops_pair(5);
            let doubled: Vec<LaunchRecord> = [five.clone(), five.clone()].concat();
            let s = summarize(
                &doubled,
                json!({"launches": 5, "max_load": 1.0}),
                Value::Null,
            );
            assert!(
                s.integrity.iter().any(|p| p.contains("duplicate")),
                "{:?}",
                s.integrity
            );
            let s = summarize(&five, json!({"launches": 6, "max_load": 1.0}), Value::Null);
            assert!(
                s.integrity.iter().any(|p| p.contains("expected 6")),
                "{:?}",
                s.integrity
            );
            let s = summarize(&five, json!({"launches": 5, "max_load": 1.0}), Value::Null);
            assert!(s.integrity.is_empty(), "{:?}", s.integrity);
            let mut drifted = five.clone();
            drifted[0].validity = Validity {
                valid: false,
                reasons: vec![Reason::Errors],
                flags: vec![],
            };
            let s = summarize(
                &drifted,
                json!({"launches": 5, "max_load": 1.0}),
                Value::Null,
            );
            assert!(
                s.integrity.iter().any(|p| p.contains("validity")),
                "{:?}",
                s.integrity
            );
            let md = render_markdown(&s);
            assert!(md.contains("Not the §5 measurement"), "{md}");
        }

        /// F2: six copies of an N=5 raw file are not 30 launches.
        #[test]
        fn duplicated_records_never_reach_a_verdict() {
            let five = fileops_pair(5);
            let six_copies: Vec<LaunchRecord> = (0..6).flat_map(|_| five.iter().cloned()).collect();
            // A quiet threshold that every copy meets: only the duplicates can
            // withhold the verdict.
            let s = summarize(
                &six_copies,
                json!({"launches": 5, "max_load": 1.0}),
                Value::Null,
            );
            let c = off_vs_direct(&s, Workload::Fileops);
            assert_eq!(c.startup_verdict, Some(Verdict::Insufficient));
            assert!(!s.integrity.is_empty());
            let md = render_markdown(&s);
            assert!(md.contains("Not the §5 measurement"), "{md}");
        }

        /// F3: an observer that silently drops events (no gap) is excluded.
        #[test]
        fn a_silent_undercount_is_excluded() {
            let mut r = jailed(Observe::On, 100, 900);
            r.receipt
                .as_mut()
                .unwrap()
                .coverage
                .get_mut("fs.write")
                .unwrap()
                .observed_count = Some(1); // the fileops workload makes 15,000
            r.receipt
                .as_mut()
                .unwrap()
                .coverage
                .get_mut("exec")
                .unwrap()
                .observed_count = Some(0);
            assert!(!validate(&r).valid, "{:?}", validate(&r));
        }

        /// F8: the exec-confirmation flag accepts only the tool-failure code 1.
        #[test]
        fn the_unconfirmed_flag_accepts_only_exit_1() {
            for code in [2, 126, 127, 137, 255] {
                let mut r = jailed(Observe::Off, 100, 300);
                let rc = r.receipt.as_mut().unwrap();
                rc.outcome_kind = "unknown".to_owned();
                rc.outcome_code = None;
                rc.outcome_cause = Some(EXEC_UNCONFIRMED.to_owned());
                r.launcher.as_mut().unwrap().status.code = Some(code);
                assert!(!validate(&r).valid, "exit {code}");
            }
        }

        /// F7: a verdict is never taken over the survivors of an exclusion.
        #[test]
        fn survivors_of_an_exclusion_get_no_verdict() {
            let mut recs = many(|_| direct(Session::Plain, 2, 200), 40);
            recs.extend(many(
                |i| {
                    let slow = i >= 30;
                    let mut r = jailed(Observe::Off, if slow { 900 } else { 100 }, 1200);
                    if slow {
                        r.launcher.as_mut().unwrap().timed_out = true;
                    }
                    r
                },
                40,
            ));
            // Quiet, clean raw data: only the exclusions can withhold it.
            let s = summarize(&recs, quiet(), Value::Null);
            assert!(s.integrity.is_empty(), "{:?}", s.integrity);
            let c = off_vs_direct(&s, Workload::Fileops);
            assert_eq!((c.subject_valid, c.subject_excluded), (30, 10));
            assert_eq!(c.startup_verdict, Some(Verdict::Insufficient));
        }

        /// F2/F9: a record of another schema is not summarised as this one.
        #[test]
        fn a_foreign_record_schema_is_refused() {
            let mut r = direct(Session::Plain, 2, 200);
            r.schema = "xtask.perf.launch/999".to_owned();
            let line = serde_json::to_vec(&r).unwrap();
            let back: LaunchRecord = serde_json::from_slice(&line).unwrap();
            let s = summarize(&[back], Value::Null, Value::Null);
            assert!(s.cells.iter().all(|c| c.valid == 0), "{:?}", s.cells);
        }
    }
}
