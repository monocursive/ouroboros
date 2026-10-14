#![cfg(target_os = "linux")]
//! The ptrace observer's precision (jail-v1 §11.2, §11.4, §15 O01, O03,
//! O05).
//!
//! The promise under test is the one §11.4 makes of every covered call: its
//! result is reported, or its classes carry a gap — never silence, and never
//! a gap for a call that had no effect. Each finding here was reproduced by
//! a failing test before its fix:
//!
//! - O-2: a covered call interrupted by a signal whose handler lacks
//!   `SA_RESTART` shows the tracer `-ERESTARTSYS` at its syscall-exit stop.
//!   The kernel turns that into `EINTR` only later, when it sets up the
//!   handler; no re-entry follows. The observer took every restart code for
//!   a restart, so the `EINTR` result was never emitted and the class read
//!   active. The observer now follows the call to the kernel's decision: a
//!   re-entry at the same instruction (restarted), the handler's entry
//!   (`EINTR` or restarted, from the restart code and the frame the kernel
//!   wrote), or a death (no result, no effect); anything else is a
//!   `restart_unresolved` gap.
//! - O-1: with the in-flight table full, a read-only open — outside the
//!   closed set — was refused as `inflight_exhausted` before the read-only
//!   filter ran, so reads became loss.
//! - O-3 is reproduced at the session seam (`session.rs`), where the kill can
//!   be placed inside the tracer's own window; the stress check here shows
//!   the same window through the real tracer loop.
//!
//! The fixture is a C program built at test time
//! (`fixtures/tracer_precision.c`, through `common/observer.rs`). Every
//! process signalled is one these tests started; every file is under a
//! private temporary directory.

use std::ops::Deref;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ouro_fixture::harness::{Jail, Run};
use ouro_jail::platform::linux::tracer::{
    ClosedOp, GapReason, OpSet, TracerConfig, TracerEvent, narrowing_filter_bytes,
};
use ouro_jail::policy::ProfileName;
use serde_json::Value;

mod common;

use common::observer::{
    Fixture, Observed, Report, assert_active, attach, audit_events, collect, mkfifo,
    native_expectation, serial, spawn_launcher,
};

static FIXTURE: Fixture = Fixture {
    name: "tracer_precision",
    source: include_str!("fixtures/tracer_precision.c"),
    pthread: true,
    filter: narrowing_filter_bytes,
};

/// The syscall the native table reports for the fixture's `native_mkdir`.
fn mkdir_syscall() -> &'static str {
    native_expectation("mkdir", ClosedOp::Mkdir).0
}

/// What one run under the bare tracer produced: the fixture's lines, and
/// what the observer said.
struct Traced {
    out: Vec<Report>,
    observed: Observed,
    launcher: libc::pid_t,
}

impl Deref for Traced {
    type Target = Observed;

    fn deref(&self) -> &Observed {
        &self.observed
    }
}

impl Traced {
    /// Results whose first path argument is `path`.
    fn results_on(&self, path: &str) -> Vec<(ClosedOp, &'static str, i64)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Syscall {
                    op,
                    syscall,
                    args,
                    ret,
                    ..
                } if args
                    .path
                    .as_ref()
                    .is_some_and(|p| p.bytes == path.as_bytes()) =>
                {
                    Some((*op, *syscall, *ret))
                }
                _ => None,
            })
            .collect()
    }

    /// `connect` results.
    fn connects(&self) -> Vec<i64> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Syscall {
                    op: ClosedOp::Connect,
                    ret,
                    ..
                } => Some(*ret),
                _ => None,
            })
            .collect()
    }

    /// The launcher's process exit status, from its `Exit`.
    fn exit_status(&self) -> Option<i32> {
        self.events.iter().find_map(|event| match event {
            TracerEvent::Exit { pid, status, .. } if *pid == self.launcher => Some(*status),
            _ => None,
        })
    }

    fn describe(&self) -> String {
        self.events
            .iter()
            .map(|event| format!("{event:?}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    }
}

/// Run the fixture under the bare tracer: the filter installed by the
/// launcher, `Tracer::attach`, release, every event until `Finished`.
fn observe(argv: &[&dyn AsRef<std::ffi::OsStr>], config: TracerConfig) -> Traced {
    let built = FIXTURE.build().expect("built");
    observe_image(&built.helper, argv, config, Duration::ZERO)
}

/// [`observe`], launching `image` (a copy of the fixture), and reading no
/// event until the tree has ended and `idle` has passed: a consumer that is
/// not reading.
fn observe_image(
    image: &Path,
    argv: &[&dyn AsRef<std::ffi::OsStr>],
    config: TracerConfig,
    idle: Duration,
) -> Traced {
    let built = FIXTURE.build().expect("built");
    let mut command = built.launcher();
    command.arg(image).args(argv);
    let mut run = spawn_launcher(command);
    let tracer = attach(run.pid, config);
    run.release();
    let out = run.lines();
    std::thread::sleep(idle);
    Traced {
        out,
        observed: collect(tracer, Duration::from_secs(60)),
        launcher: run.pid,
    }
}

/// A private work directory holding a FIFO nobody reads.
struct Work {
    _dir: tempfile::TempDir,
    root: PathBuf,
    fifo: PathBuf,
}

fn work() -> Work {
    let dir = common::private_tempdir();
    let root = dir.path().to_path_buf();
    let fifo = root.join("fifo");
    mkfifo(&fifo);
    Work {
        _dir: dir,
        root,
        fifo,
    }
}

fn s(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Interrupt a parked call under the bare tracer.
fn interrupt(how: &str, kind: &str) -> (Work, Traced) {
    let w = work();
    let observed = observe(
        &[&"interrupt", &how, &kind, &w.fifo, &w.root],
        TracerConfig::default(),
    );
    (w, observed)
}

/// The one result the parked call produced: the FIFO open, or the one
/// `connect` of the parked thread (the fixture's own first connect, which
/// fills the backlog, is the other).
fn parked_results(kind: &str, w: &Work, observed: &Traced) -> Vec<i64> {
    if kind == "open" {
        observed
            .results_on(&s(&w.fifo))
            .into_iter()
            .map(|(op, syscall, ret)| {
                assert_eq!((op, syscall), (ClosedOp::Open, "openat"));
                ret
            })
            .collect()
    } else {
        // The first connect filled the backlog and succeeded.
        let mut connects = observed.connects();
        assert!(
            !connects.is_empty() && connects[0] == 0,
            "the backlog-filling connect: {connects:?}\n  {}",
            observed.describe()
        );
        connects.remove(0);
        connects
    }
}

// ===========================================================================
// O-2 at the tracer seam
// ===========================================================================

/// O-2: a handler without `SA_RESTART`. The kernel returns `-ERESTARTSYS`
/// at the syscall exit and `EINTR` to the program; the one result the call
/// has is `EINTR`, and it is reported — no gap, no silence.
fn eintr_is_the_result(how: &str, kind: &str) {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    let (w, observed) = interrupt(how, kind);
    let label = format!("{how}/{kind}");
    let out = &observed.out;
    assert_eq!(Report::find(out, "parked").raw, 0, "{label}: {out:#?}");
    let call = Report::find(out, "call");
    assert_eq!(
        call.errno,
        libc::EINTR,
        "{label}: the fixture's own view: {out:#?}"
    );
    assert_eq!(Report::find(out, "handled").raw, 1, "{label}: {out:#?}");
    assert_eq!(
        parked_results(kind, &w, &observed),
        vec![-i64::from(libc::EINTR)],
        "{label}: one call, one result, and it is EINTR:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.gaps(),
        vec![],
        "{label}: an interrupted call is not loss:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{label}: {:?}",
        observed.summary
    );
    assert_eq!(
        observed.summary.restarts, 0,
        "{label}: nothing was restarted: {:?}",
        observed.summary
    );
    assert_eq!(
        observed.summary.interrupted, 1,
        "{label}: decided at the handler's entry: {:?}",
        observed.summary
    );
    assert_eq!(observed.exit_status(), Some(0), "{label}");
}

#[test]
fn j4_o2_a_handler_without_sa_restart_makes_eintr_the_result_open() {
    eintr_is_the_result("eintr", "open");
}

#[test]
fn j4_o2_a_handler_without_sa_restart_makes_eintr_the_result_connect() {
    eintr_is_the_result("eintr", "connect");
}

/// The same through `SA_SIGINFO` on an alternate signal stack: the frame
/// the kernel wrote is found from the handler's own arguments, wherever
/// the stack is.
#[test]
fn j4_o2_eintr_through_sa_siginfo_on_an_alternate_stack() {
    eintr_is_the_result("siginfo-alt", "open");
}

/// Two interruptions of one call: an ignored signal (restarted), then
/// a handler without `SA_RESTART` (`EINTR`). One call, one result.
#[test]
fn j4_o2_a_restart_then_an_eintr_in_one_call_is_one_result() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    let (w, observed) = interrupt("twice", "open");
    let out = &observed.out;
    assert_eq!(Report::find(out, "reparked").raw, 0, "{out:#?}");
    assert_eq!(Report::find(out, "call").errno, libc::EINTR, "{out:#?}");
    assert_eq!(
        parked_results("open", &w, &observed),
        vec![-i64::from(libc::EINTR)],
        "\n  {}",
        observed.describe()
    );
    assert_eq!(observed.gaps(), vec![], "\n  {}", observed.describe());
    assert_eq!(observed.summary.restarts, 1, "{:?}", observed.summary);
    assert_eq!(observed.summary.interrupted, 1, "{:?}", observed.summary);
    assert_eq!(observed.summary.loss.total(), 0, "{:?}", observed.summary);
}

/// A handler without `SA_RESTART` that makes a covered call of its own:
/// both are results, the interrupted call's `EINTR` first — it was decided
/// before the handler ran — and the handler's `mkdir` after it.
#[test]
fn j4_o2_a_handler_s_own_call_follows_the_eintr_it_interrupted() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    let (w, observed) = interrupt("mkdir", "open");
    let out = &observed.out;
    assert_eq!(Report::find(out, "call").errno, libc::EINTR, "{out:#?}");
    assert_eq!(Report::find(out, "handler_mkdir").raw, 1, "{out:#?}");
    let fifo = s(&w.fifo);
    let h = s(&w.root.join("h"));
    let order: Vec<(String, i64)> = observed
        .events
        .iter()
        .filter_map(|event| match event {
            TracerEvent::Syscall { args, ret, .. } => {
                let path = String::from_utf8_lossy(&args.path.as_ref()?.bytes).into_owned();
                (path == fifo || path == h).then_some((path, *ret))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        order,
        vec![(fifo, -i64::from(libc::EINTR)), (h, 0)],
        "\n  {}",
        observed.describe()
    );
    assert_eq!(observed.gaps(), vec![], "\n  {}", observed.describe());
}

/// A handler with `SA_RESTART`: the kernel re-enters the call, which then
/// completes. One result, the restarted call's, and no gap.
fn restarted_is_one_result(how: &str, kind: &str) {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    let (w, observed) = interrupt(how, kind);
    let label = format!("{how}/{kind}");
    let out = &observed.out;
    assert_eq!(Report::find(out, "reparked").raw, 0, "{label}: {out:#?}");
    let call = Report::find(out, "call");
    assert!(call.raw >= 0, "{label}: the call completed: {out:#?}");
    let results = parked_results(kind, &w, &observed);
    assert_eq!(
        results.len(),
        1,
        "{label}: one call, one result:\n  {}",
        observed.describe()
    );
    assert!(
        results[0] >= 0,
        "{label}: the restarted call's success: {results:?}"
    );
    if kind == "connect" {
        assert_eq!(results[0], call.ret(), "{label}");
    }
    assert_eq!(
        observed.gaps(),
        vec![],
        "{label}: a restart is not loss:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.summary.restarts, 1,
        "{label}: the restart was recognised: {:?}",
        observed.summary
    );
    assert_eq!(observed.summary.loss.total(), 0, "{label}");
}

#[test]
fn j4_o2_a_handler_with_sa_restart_gives_the_restarted_result_open() {
    restarted_is_one_result("restart", "open");
}

#[test]
fn j4_o2_a_handler_with_sa_restart_gives_the_restarted_result_connect() {
    restarted_is_one_result("restart", "connect");
}

/// No handler: a signal the tracee ignores still interrupts a traced call
/// (the kernel reports it to the tracer), and the kernel re-enters it.
#[test]
fn j4_o2_an_ignored_signal_restarts_the_call() {
    restarted_is_one_result("ignored", "open");
}

#[test]
fn j4_o2_a_default_ignored_signal_restarts_the_call() {
    restarted_is_one_result("default", "open");
}

/// A fatal signal in the window between the restart-coded exit and the
/// kernel's decision: the process dies inside the call. A restart code
/// means the call did nothing, and no result was ever returned: no result,
/// no gap, and the process's own death is reported.
#[test]
fn j4_o2_a_fatal_signal_inside_the_call_is_no_result_and_no_loss() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    let (w, observed) = interrupt("fatal", "open");
    let out = &observed.out;
    assert_eq!(Report::find(out, "parked").raw, 0, "{out:#?}");
    assert!(out.iter().all(|line| line.label != "survived"), "{out:#?}");
    let status = observed.exit_status().expect("the process's exit");
    assert!(
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTERM,
        "status {status:#x}"
    );
    assert_eq!(
        parked_results("open", &w, &observed),
        Vec::<i64>::new(),
        "\n  {}",
        observed.describe()
    );
    assert_eq!(observed.gaps(), vec![], "\n  {}", observed.describe());
    assert_eq!(observed.summary.loss.total(), 0, "{:?}", observed.summary);
    assert_eq!(
        observed.summary.restarts_unfinished, 1,
        "the call died waiting for the kernel's decision: {:?}",
        observed.summary
    );
}

// ===========================================================================
// O-1 at the tracer seam
// ===========================================================================

/// O-1: under an in-flight bound of one, held by a parked open, every
/// covered call is refused a slot (`inflight_exhausted`, naming its own
/// operation) — and no read-only open is: those are outside the closed set,
/// are filtered at their entry, and never consume or are refused a slot.
#[test]
fn j4_o1_read_only_opens_are_never_inflight_loss() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    const ROUNDS: u64 = 10;
    let w = work();
    let observed = observe(
        &[&"inflight", &w.fifo, &w.root, &ROUNDS.to_string()],
        TracerConfig {
            inflight_max: 1,
            ..TracerConfig::default()
        },
    );
    let out = &observed.out;
    assert_eq!(Report::find(out, "parked").raw, 0, "{out:#?}");
    assert_eq!(
        Report::find(out, "covered").raw,
        2 * ROUNDS as i64,
        "{out:#?}"
    );
    assert_eq!(
        Report::find(out, "reads").raw,
        2 * ROUNDS as i64,
        "{out:#?}"
    );
    assert_eq!(Report::find(out, "after").raw, 0, "{out:#?}");
    let summary = &observed.summary;
    assert_eq!(
        summary.loss.inflight_rejected,
        2 * ROUNDS,
        "only the covered calls were refused: {summary:?}"
    );
    assert!(
        summary.filtered_readonly_opens >= 2 * ROUNDS,
        "the reads were filtered, not refused: {summary:?}"
    );
    let exhausted: Vec<(OpSet, Option<u64>)> = observed
        .gaps()
        .into_iter()
        .filter(|(reason, _, _)| *reason == GapReason::InflightExhausted)
        .map(|(_, ops, count)| (ops, count))
        .collect();
    let lost: u64 = exhausted.iter().filter_map(|(_, count)| *count).sum();
    assert_eq!(lost, 2 * ROUNDS, "{exhausted:?}");
    for (ops, _) in &exhausted {
        assert!(
            !ops.contains(ClosedOp::Open),
            "a gap naming an open: only reads were opened while the slot was held: {ops:?}"
        );
    }
    // The slot came back: the mkdir after the release is a result.
    assert_eq!(
        observed.results_on(&s(&w.root.join("after"))),
        vec![(ClosedOp::Mkdir, mkdir_syscall(), 0)]
    );
}

// ===========================================================================
// O-3 through the tracer loop
// ===========================================================================

/// O-3, measured through the real tracer loop: threads that make covered
/// calls without pause, ended by `exit_group`. Every thread is killed
/// wherever it is; some are at their seccomp entry stop, and the kernel
/// skips a call whose thread has a fatal signal pending after that stop.
/// A thread found killed at a stop the observer never resumed made no call,
/// which is not loss: no `syscall_info_unavailable`, ever. A call the
/// observer had let run when the kill came may have had its effect, so
/// `entry_abandoned` stays a gap there — the only reason allowed.
///
/// The check means something only if the kill did land at such a stop: at
/// least `RUNS` races are run, and more, up to
/// `MAX_RUNS`, until one has; if none ever does, the test fails rather than
/// pass having checked nothing.
#[test]
fn j4_o3_a_group_exit_racing_entry_stops_is_never_syscall_info_loss() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    const RUNS: usize = 40;
    const MAX_RUNS: usize = 400;
    let mut seen_abandoned = 0u64;
    let mut killed = 0u64;
    let mut unavailable = Vec::new();
    let mut runs = 0;
    for run in 0..MAX_RUNS {
        if run >= RUNS && killed > 0 {
            break;
        }
        runs += 1;
        let w = work();
        let observed = observe(
            &[&"killrace", &w.root, &"4", &"30"],
            TracerConfig::default(),
        );
        let status = observed.exit_status().expect("the group's exit");
        assert_eq!(libc::WEXITSTATUS(status), 7, "run {run}");
        for (reason, ops, count) in observed.gaps() {
            match reason {
                GapReason::EntryAbandoned => seen_abandoned += count.unwrap_or(0),
                other => unavailable.push(format!("run {run}: {other:?} {ops:?} {count:?}")),
            }
        }
        killed += observed.summary.killed_at_entry;
        if observed.summary.loss.syscall_info_unavailable > 0 {
            unavailable.push(format!("run {run}: {:?}", observed.summary.loss));
        }
    }
    println!("entry_abandoned across {runs} runs: {seen_abandoned}; killed at entry: {killed}");
    assert_eq!(
        unavailable,
        Vec::<String>::new(),
        "a thread killed at a stop it was never resumed from made no call"
    );
    assert!(
        killed > 0,
        "no kill landed at an unresumed entry stop in {runs} races: the window was never tested"
    );
}

// ===========================================================================
// Through the product
// ===========================================================================

/// Whether this host can run a live check of `profile`.
fn live(profile: &str) -> bool {
    let profile = ProfileName::parse(profile).expect("a built-in profile");
    common::profile_live(profile)
}

/// Audit results naming this workspace-relative path.
fn results_on<'a>(run: &'a Run, relative: &str) -> Vec<&'a Value> {
    audit_events(run)
        .into_iter()
        .filter(|event| {
            event["fields"]["path"]["kind"] == "workspace_relative"
                && event["fields"]["path"]["value"] == relative
        })
        .collect()
}

/// The class entry, asserted degraded with a null count and one gap of
/// `reason` naming it; returns that gap.
fn assert_degraded<'a>(receipt: &'a Value, class: &str, reason: &str) -> &'a Value {
    let entry = &receipt["coverage"][class];
    assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
    assert_eq!(entry["observed_count"], Value::Null, "{class}: {entry:#}");
    let gaps: Vec<&Value> = entry["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|gap| gap["reason"] == reason)
        .collect();
    assert_eq!(gaps.len(), 1, "{class}: one {reason} gap: {entry:#}");
    gaps[0]
}

/// O-2 through the product, strict: the interrupted open is an `fs.write`
/// result with `EINTR`, the class is active and counts it, and nothing is
/// lost — so a strict attempt runs to its end and exits 0. An observer that
/// took the restart code for a restart would leave the call out of an
/// `active` count, with no result naming the FIFO.
fn eintr_through_the_product(profile: &str) {
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some(c) = FIXTURE.case_on(Jail::new().unwrap(), profile, "strict") else {
        return;
    };
    let argv = c.argv("interrupt", &[&"eintr", &"open", &c.fifo, &c.ops]);
    let run = c.jail.target(argv).run().unwrap();
    let out = Report::parse_all(&run.stdout_text());
    let settled = common::settled(&run);
    assert_eq!(
        Report::find(&out, "call").errno,
        libc::EINTR,
        "{profile}: {out:#?}"
    );
    assert_eq!(
        run.code(),
        Some(0),
        "{profile}: stderr {}",
        run.stderr_text()
    );
    let fifo = results_on(&run, "fifo");
    assert_eq!(
        fifo.len(),
        1,
        "{profile}: one result for the call: {fifo:#?}"
    );
    assert_eq!(fifo[0]["operation"], "fs.write", "{profile}: {:#}", fifo[0]);
    assert_eq!(
        fifo[0]["outcome"]["errno"], "EINTR",
        "{profile}: {:#}",
        fifo[0]
    );
    assert_eq!(fifo[0]["outcome"]["ok"], false, "{profile}");
    // The interrupted open is the only covered filesystem call the fixture
    // makes; the target's exec and exit are the exec class.
    assert_active(&settled, "fs.write", 1);
    assert_active(&settled, "fs.deny", 0);
    assert_active(&settled, "exec", 2);
    assert_active(&settled, "net", 0);
}

#[test]
fn j4_o2_eintr_is_counted_through_the_product_tool() {
    eintr_through_the_product("tool");
}

#[test]
fn j4_o2_eintr_is_counted_through_the_product_none() {
    eintr_through_the_product("none");
}

/// O-1 through the product, with the shrink-only in-flight seam: the lost
/// count is exactly the covered calls made while the parked open held the
/// slot — the reads made meanwhile are outside the closed set and are not
/// loss. A bound checked before the read-only filter would count every read
/// too.
fn inflight_through_the_product(profile: &str) {
    const ROUNDS: u64 = 10;
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some(c) = FIXTURE.case_on(
        Jail::new()
            .unwrap()
            .env("OURO_JAIL_TEST_TRACER_INFLIGHT", "1"),
        profile,
        "best-effort",
    ) else {
        return;
    };
    let argv = c.argv("inflight", &[&c.fifo, &c.ops, &ROUNDS.to_string()]);
    let run = c.jail.target(argv).run().unwrap();
    let out = Report::parse_all(&run.stdout_text());
    let settled = common::settled(&run);
    assert_eq!(Report::find(&out, "parked").raw, 0, "{profile}: {out:#?}");
    assert_eq!(
        Report::find(&out, "covered").raw,
        2 * ROUNDS as i64,
        "{profile}"
    );
    assert_eq!(
        Report::find(&out, "reads").raw,
        2 * ROUNDS as i64,
        "{profile}"
    );
    for class in ["fs.write", "fs.deny"] {
        let gap = assert_degraded(&settled, class, "inflight_exhausted");
        assert_eq!(
            gap["lost_count"],
            2 * ROUNDS,
            "{profile}/{class}: the covered calls, not the reads: {gap:#}"
        );
    }
    assert_active(&settled, "exec", 2);
    assert_active(&settled, "net", 0);
    assert_eq!(
        results_on(&run, "ops/after").len(),
        1,
        "{profile}: the slot came back"
    );
    assert_eq!(
        run.code(),
        Some(0),
        "{profile}: best-effort preserves the child's natural exit despite recorded loss"
    );
}

#[test]
fn j4_o1_inflight_loss_counts_only_covered_calls_through_the_product_tool() {
    inflight_through_the_product("tool");
}

#[test]
fn j4_o1_inflight_loss_counts_only_covered_calls_through_the_product_none() {
    inflight_through_the_product("none");
}

// ===========================================================================
// A non-leader exec, a child's own listener, an untraced clone, the queue
// budget, and a restart the handler rewrote
// ===========================================================================

/// The gaps of `reason`, as `(ops, count)`.
fn gaps_of(observed: &Traced, reason: GapReason) -> Vec<(OpSet, Option<u64>)> {
    observed
        .gaps()
        .into_iter()
        .filter(|(r, _, _)| *r == reason)
        .map(|(_, ops, count)| (ops, count))
        .collect()
}

/// Where in the event stream the first event matching `pick` is.
fn position(observed: &Traced, pick: impl Fn(&TracerEvent) -> bool) -> Option<usize> {
    observed.events.iter().position(pick)
}

/// A non-leader exec with the leader's call in flight, at the tracer seam
/// (an honesty finding). The leader parks in
/// `openat(FIFO, O_WRONLY)`; a worker `execve`s, which destroys the leader
/// with its open in flight and gives the worker the leader's id. The open
/// never returns — the fixture never prints `leader_open_returned`.
///
/// With an in-flight bound of one the worker's own `execve` entry cannot be
/// followed (the leader's open holds the slot). Left on the thread that now
/// bears the leader's id, the leader's stale open would pair with the
/// `execve`'s own syscall exit: an invented `openat = 0`. The rule:
/// at a non-leader exec the leader's entry can no longer return, whatever
/// the worker carried, so it is one `entry_abandoned` gap of its own classes,
/// never a result. The unbounded run is the control.
#[test]
fn j4_w3_a_leaders_entry_is_never_paired_with_a_non_leader_execs_exit() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    let built = FIXTURE.build().expect("built");
    let helper = &built.helper;
    for inflight in [1usize, 16_384] {
        let w = work();
        let observed = observe(
            &[&"leader-exec", &w.fifo, helper],
            TracerConfig {
                inflight_max: inflight,
                ..TracerConfig::default()
            },
        );
        let label = format!("in-flight bound {inflight}");
        let out = &observed.out;
        assert_eq!(
            Report::find(out, "leader_parked").raw,
            1,
            "{label}: {out:#?}"
        );
        assert!(
            out.iter().all(|l| l.label != "leader_open_returned"),
            "{label}: the leader's open never returned: {out:#?}"
        );
        assert_eq!(
            observed.results_on(&s(&w.fifo)),
            vec![],
            "{label}: an open that never returned has no result:\n  {}",
            observed.describe()
        );
        assert_eq!(
            gaps_of(&observed, GapReason::EntryAbandoned),
            vec![(OpSet::of(ClosedOp::Open), Some(1))],
            "{label}: the leader's open is one entry_abandoned gap of its classes:\n  {}",
            observed.describe()
        );
        let refused = gaps_of(&observed, GapReason::InflightExhausted);
        if inflight == 1 {
            assert_eq!(
                refused,
                vec![(OpSet::of(ClosedOp::Exec), Some(1))],
                "{label}: the worker's execve could not be followed:\n  {}",
                observed.describe()
            );
        } else {
            assert_eq!(refused, vec![], "{label}");
        }
        assert_eq!(observed.exit_status(), Some(0), "{label}: exit0 ran");
        assert_eq!(
            observed.summary.ops.get(ClosedOp::Open),
            0,
            "{label}: {:?}",
            observed.summary
        );
    }
}

/// The same through the product: `tool` and `none` with the shrink-only
/// in-flight seam at one. The invented result would be an `fs.write` result
/// `ok: true` on the FIFO, in the settled receipt, for an open that never
/// returned.
fn leader_exec_through_the_product(profile: &str) {
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some(c) = FIXTURE.case_on(
        Jail::new()
            .unwrap()
            .env("OURO_JAIL_TEST_TRACER_INFLIGHT", "1"),
        profile,
        "best-effort",
    ) else {
        return;
    };
    let argv = c.argv("leader-exec", &[&c.fifo, &c.helper]);
    let run = c.jail.target(argv).run().unwrap();
    let out = Report::parse_all(&run.stdout_text());
    let settled = common::settled(&run);
    assert_eq!(
        Report::find(&out, "leader_parked").raw,
        1,
        "{profile}: {out:#?}"
    );
    assert!(
        out.iter().all(|l| l.label != "leader_open_returned"),
        "{profile}: {out:#?}"
    );
    assert_eq!(
        results_on(&run, "fifo"),
        Vec::<&Value>::new(),
        "{profile}: no result for an open that never returned"
    );
    for class in ["fs.write", "fs.deny"] {
        let gap = assert_degraded(&settled, class, "entry_abandoned");
        assert_eq!(gap["lost_count"], 1, "{profile}/{class}: {gap:#}");
    }
    let gap = assert_degraded(&settled, "exec", "inflight_exhausted");
    assert_eq!(
        gap["lost_count"], 1,
        "{profile}: the worker's execve: {gap:#}"
    );
    assert_active(&settled, "net", 0);
    assert_eq!(
        run.code(),
        Some(0),
        "{profile}: best-effort preserves the child's natural exit despite recorded loss: {}",
        run.stderr_text()
    );
}

#[test]
fn j4_w3_a_non_leader_exec_invents_no_result_through_the_product_tool() {
    leader_exec_through_the_product("tool");
}

#[test]
fn j4_w3_a_non_leader_exec_invents_no_result_through_the_product_none() {
    leader_exec_through_the_product("none");
}

/// A child's own notification listener, refused a slot. A thread's open
/// holds the only
/// in-flight slot while the main thread asks for its own notification
/// listener: the request cannot be followed to its return, so the observer
/// cannot know whether a listener now exists, and must assume one does —
/// the open-ended `child_notification_listener` gap in every class, with no
/// count. A one-count `inflight_exhausted` gap with an end would understate
/// it: the listener then hides both `mkdir`s (continued with no stop). The
/// unbounded run is the control.
#[test]
fn j4_w3_a_listener_refused_a_slot_is_the_open_ended_gap_of_its_kind() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    for inflight in [1usize, 16_384] {
        let w = work();
        let observed = observe(
            &[&"hide", &w.fifo, &w.root, &"listener"],
            TracerConfig {
                inflight_max: inflight,
                ..TracerConfig::default()
            },
        );
        let label = format!("in-flight bound {inflight}");
        let out = &observed.out;
        assert_eq!(Report::find(out, "parked").raw, 0, "{label}: {out:#?}");
        assert!(Report::find(out, "listener").raw >= 0, "{label}: {out:#?}");
        assert_eq!(Report::find(out, "hidden1").raw, 0, "{label}: {out:#?}");
        assert_eq!(Report::find(out, "hidden2").raw, 0, "{label}: {out:#?}");
        assert_eq!(Report::find(out, "released").errno, libc::EINTR, "{label}");
        for hidden in ["hidden1", "hidden2"] {
            assert_eq!(
                observed.results_on(&s(&w.root.join(hidden))),
                vec![],
                "{label}: the listener continued {hidden} with no stop"
            );
        }
        assert_eq!(
            observed.gaps(),
            vec![(GapReason::ChildNotificationListener, OpSet::ALL, None)],
            "{label}: one open-ended listener gap, and no bounded gap in its place:\n  {}",
            observed.describe()
        );
        assert_eq!(
            observed.results_on(&s(&w.fifo)),
            vec![(ClosedOp::Open, "openat", -i64::from(libc::EINTR))],
            "{label}"
        );
    }
}

/// `clone(CLONE_UNTRACED)`, refused a slot: the clone runs unfollowed and
/// makes a task nothing traces. It is the open-ended `untraced_descendant`
/// gap, as when it is followed, never a one-count `inflight_exhausted` gap
/// with an end.
#[test]
fn j4_w3_an_untraced_clone_refused_a_slot_is_the_open_ended_gap_of_its_kind() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    for inflight in [1usize, 16_384] {
        let w = work();
        let observed = observe(
            &[&"hide", &w.fifo, &w.root, &"untraced"],
            TracerConfig {
                inflight_max: inflight,
                ..TracerConfig::default()
            },
        );
        let label = format!("in-flight bound {inflight}");
        let out = &observed.out;
        assert_eq!(Report::find(out, "parked").raw, 0, "{label}: {out:#?}");
        assert!(Report::find(out, "clone").raw > 0, "{label}: {out:#?}");
        assert_eq!(
            Report::find(out, "untraced_mkdir").errno,
            libc::ENOSYS,
            "{label}: the untraced child fails closed: {out:#?}"
        );
        assert_eq!(
            observed.gaps(),
            vec![(GapReason::UntracedDescendant, OpSet::ALL, None)],
            "{label}: one open-ended untraced-descendant gap:\n  {}",
            observed.describe()
        );
        assert_eq!(
            observed.results_on(&s(&w.root.join("hidden2"))),
            vec![(ClosedOp::Mkdir, mkdir_syscall(), 0)],
            "{label}: the slot came back"
        );
    }
}

/// The queue budget, at the tracer seam: the §11.4 queue budget
/// (`queue_bytes_max`, which the observer plan records) must bound what the
/// observer holds on behalf of a consumer that is not reading — the
/// critical facts (`Exit`, `Gap`, `Finished`) aside, which §11.4 exempts.
/// Two hundred execs, each carrying a ~2.8 KiB pathname, while nothing
/// reads; then everything is read. A handoff channel outside the budget (66
/// slots) would hold ~200 KiB of `Exec` events under a 16 KiB budget.
#[test]
fn j4_w3_the_queue_budget_bounds_what_is_held_for_a_consumer_not_reading() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    const BUDGET: usize = 16_384;
    let built = FIXTURE.build().expect("built");
    let helper = &built.helper;
    let dir = common::private_tempdir();
    let image = dir.path().join("j4-precision");
    std::fs::copy(helper, &image).unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A long pathname to the same image: many "./" components.
    let mut long = dir.path().to_path_buf().into_os_string();
    for _ in 0..1400 {
        long.push("/.");
    }
    long.push("/j4-precision");
    let long = PathBuf::from(long);
    let config = TracerConfig {
        queue_bytes_max: BUDGET,
        ..TracerConfig::default()
    };
    let observed = observe_image(
        &long,
        &[&"reexec", &"200", &long],
        config,
        Duration::from_millis(500),
    );
    assert_eq!(
        Report::find(&observed.out, "done").raw,
        0,
        "{:#?}",
        observed.out
    );
    let mut held = 0usize;
    let mut execs = 0usize;
    for event in &observed.events {
        let snapshots = match event {
            TracerEvent::Exec { path, .. } => {
                execs += 1;
                path.as_ref().map_or(0, |p| p.bytes.len())
            }
            TracerEvent::Syscall { args, .. } => {
                args.path.as_ref().map_or(0, |p| p.bytes.len())
                    + args.path2.as_ref().map_or(0, |p| p.bytes.len())
            }
            // Exempt from every queue bound (§11.4).
            TracerEvent::Exit { .. }
            | TracerEvent::Gap { .. }
            | TracerEvent::UntracedChildExit { .. }
            | TracerEvent::Finished => continue,
            TracerEvent::Attached { .. } | TracerEvent::Fork { .. } => 0,
        };
        held += ouro_jail::platform::linux::tracer::EVENT_FIXED_BYTES + snapshots;
    }
    println!(
        "{execs} Exec events delivered, {held} bytes held, {} dropped",
        observed.summary.loss.lifecycle_dropped
    );
    assert!(
        held <= BUDGET,
        "the observer held {held} bytes for a consumer that was not reading, \
         over the {BUDGET}-byte budget it records"
    );
    assert!(
        observed.summary.loss.lifecycle_dropped > 0
            && !gaps_of(&observed, GapReason::LifecycleDropped).is_empty(),
        "the budget was reached, and what it could not hold is a gap: {:?}",
        observed.summary
    );
}

/// A restart the handler rewrote, at the tracer seam. A handler installed with
/// `SA_SIGINFO | SA_RESTART` interrupts a parked call; the kernel prepares
/// the restart in the handler's frame (`rax` = the call's number, `rip` back
/// on the `syscall` instruction), and the observer reads exactly that at the
/// handler's entry. The handler then rewrites its own frame so the thread
/// sees `EINTR` and the call is never re-entered — as a sibling rewriting the
/// frame the other way before the observer reads it can make a real `EINTR`
/// look like a restart. Taking the frame at its word would leave no result
/// and no gap for a call the program saw fail. The rule: a restart
/// read from a handler's frame is settled only by the re-entry itself; the
/// thread's next covered call, when it is another, or the thread's end,
/// settles it as a `restart_unresolved` gap of the call's classes.
fn rewritten_restart_is_a_gap(how: &str, kind: &str) -> (Work, Traced) {
    let (w, observed) = interrupt(how, kind);
    let label = format!("{how}/{kind}");
    let out = &observed.out;
    assert_eq!(Report::find(out, "parked").raw, 0, "{label}: {out:#?}");
    assert_eq!(Report::find(out, "rewrote").raw, 1, "{label}: {out:#?}");
    assert_eq!(
        Report::find(out, "call").errno,
        libc::EINTR,
        "{label}: the program saw EINTR: {out:#?}"
    );
    let ops = OpSet::of(if kind == "open" {
        ClosedOp::Open
    } else {
        ClosedOp::Connect
    });
    assert_eq!(
        parked_results(kind, &w, &observed),
        Vec::<i64>::new(),
        "{label}: no re-entry, so no result was observed:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.gaps(),
        vec![(GapReason::RestartUnresolved, ops, Some(1))],
        "{label}: one gap of the call's classes, never silence:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.summary.restarts, 0,
        "{label}: {:?}",
        observed.summary
    );
    (w, observed)
}

#[test]
fn j4_w3_r1_a_restart_the_handler_rewrote_then_the_threads_end_is_a_gap_open() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    rewritten_restart_is_a_gap("rewrite", "open");
}

#[test]
fn j4_w3_r1_a_restart_the_handler_rewrote_then_the_threads_end_is_a_gap_connect() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    rewritten_restart_is_a_gap("rewrite", "connect");
}

/// The next covered call: the thread's `mkdir` after the rewritten
/// `EINTR` settles the call as a gap at its own entry, so the gap comes
/// before the `mkdir`'s result.
#[test]
fn j4_w3_r1_a_restart_the_handler_rewrote_then_another_call_is_a_gap_first() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    let (w, observed) = rewritten_restart_is_a_gap("rewrite-mkdir", "open");
    assert_eq!(
        Report::find(&observed.out, "after").raw,
        0,
        "{:#?}",
        observed.out
    );
    let after = s(&w.root.join("after"));
    assert_eq!(
        observed.results_on(&after),
        vec![(ClosedOp::Mkdir, mkdir_syscall(), 0)]
    );
    let gap = position(&observed, |event| {
        matches!(
            event,
            TracerEvent::Gap {
                reason: GapReason::RestartUnresolved,
                ..
            }
        )
    });
    let mkdir = position(&observed, |event| {
        matches!(
            event,
            TracerEvent::Syscall {
                op: ClosedOp::Mkdir,
                ..
            }
        )
    });
    assert!(
        gap.is_some() && gap < mkdir,
        "the gap is settled at the mkdir's entry:\n  {}",
        observed.describe()
    );
}

/// What that rule costs, pinned so it stays visible: a handler installed
/// with `SA_RESTART` that makes a covered call of its own. That call is the
/// thread's next covered call, and it is not the re-entry, so the
/// interrupted call is a `restart_unresolved` gap — conservative: the
/// observer cannot tell a call inside the handler from one after a frame the
/// handler rewrote. The re-entry that follows is then an ordinary entry with
/// its own result, and the handler's `mkdir` is a result.
#[test]
fn j4_w3_r1_a_covered_call_inside_an_sa_restart_handler_costs_one_gap() {
    let _serial = serial();
    if !common::live() || FIXTURE.built().is_none() {
        return;
    }
    let (w, observed) = interrupt("restart-mkdir", "open");
    let out = &observed.out;
    assert_eq!(Report::find(out, "reparked").raw, 0, "{out:#?}");
    assert!(
        Report::find(out, "call").raw >= 0,
        "the call completed: {out:#?}"
    );
    assert_eq!(Report::find(out, "handler_mkdir").raw, 1, "{out:#?}");
    let results = parked_results("open", &w, &observed);
    assert_eq!(results.len(), 1, "\n  {}", observed.describe());
    assert!(results[0] >= 0, "{results:?}");
    assert_eq!(
        observed.results_on(&s(&w.root.join("h"))),
        vec![(ClosedOp::Mkdir, mkdir_syscall(), 0)]
    );
    assert_eq!(
        observed.gaps(),
        vec![(
            GapReason::RestartUnresolved,
            OpSet::of(ClosedOp::Open),
            Some(1)
        )],
        "\n  {}",
        observed.describe()
    );
}
