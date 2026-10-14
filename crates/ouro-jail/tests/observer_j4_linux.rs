#![cfg(target_os = "linux")]
//! The observer's own defects: places where the ptrace observer could
//! report coverage as complete when it is not. D1, a child's own seccomp
//! filter takes calls away from it; D2, a call under another ABI; D6,
//! critical facts behind a full lifecycle backlog. The `j4_dN_…` tests carry
//! those labels.
//!
//! Each was written before its fix and failed without it. The shape is the
//! observer suite's (`common/observer.rs`): a C fixture built at test time
//! (`fixtures/observer_j4.c`) is the inside launcher (it installs the
//! narrowing filter this crate produces, blocks on its release pipe, then
//! execs), the test seizes it with `Tracer::attach`, and what the observer
//! said is compared with what the fixture says the kernel returned. The two
//! `none` receipt checks run the real `ouro-jail` over the same fixture.
//!
//! Every process these tests trace is one they start; nothing on the host is
//! inspected or changed.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use ouro_fixture::harness::{self, Jail, Run};
use ouro_jail::platform::linux::tracer::{
    ClosedOp, GapReason, OpSet, TracerConfig, TracerEvent, narrowing_filter_bytes,
};
use serde_json::Value;

// The shared tracer scaffolding, and the contract checks for the two `none`
// receipts below.
mod common;

use common::observer::{
    Fixture, Observed, Report, Work, attach, collect, launch, launch_tool, primary, serial,
};

static FIXTURE: Fixture = Fixture {
    name: "observer_j4",
    source: include_str!("fixtures/observer_j4.c"),
    pthread: true,
    filter: narrowing_filter_bytes,
};

fn setup(name: &str) -> Option<Work> {
    FIXTURE.setup(name, &[])
}

/// Whether this host has the foreign ABIs the fixture calls through (i386
/// `int 0x80`, x32): only x86_64 does. Prints `skipped:` elsewhere, or fails
/// under `OURO_CONFORMANCE=1`.
fn foreign_abis() -> bool {
    if cfg!(target_arch = "x86_64") {
        return true;
    }
    harness::skip_or_fail(
        "the i386 and x32 ABIs this check calls through exist only on x86_64; \
         a 32-bit compat ABI on this architecture is not exercised by the fixture",
    );
    false
}

impl Observed {
    /// The primary path of every result.
    fn primaries(&self) -> Vec<String> {
        self.syscalls().into_iter().map(primary).collect()
    }

    /// Gaps whose reason has this name. Matched by the name the receipt
    /// carries, which is what a consumer sees.
    fn gaps_named(&self, name: &str) -> Vec<(OpSet, Option<u64>)> {
        self.gaps()
            .into_iter()
            .filter(|(reason, _, _)| reason.as_str() == name)
            .map(|(_, ops, count)| (ops, count))
            .collect()
    }

    /// Every event but the forks, one per line.
    fn describe(&self) -> String {
        self.events
            .iter()
            .filter(|e| !matches!(e, TracerEvent::Fork { .. }))
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    }
}

/// Run `argv` under the observer's filter only, the `none` shape.
fn observe(work: &Work, argv: &[&str]) -> (Vec<Report>, Observed) {
    let mut run = launch(work, argv);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    (reports, collect(tracer, Duration::from_secs(60)))
}

// ===========================================================================
// D1: a child's own seccomp filter can take calls away from the observer
// ===========================================================================

/// D1, the listener. A child that installs its own filter with a
/// notification listener and answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE` runs
/// a closed-set call with no ptrace stop: `USER_NOTIF` outranks the
/// narrowing filter's `TRACE`. The observer cannot see that call, so it must
/// say so, for every class, from the moment the listener exists.
#[test]
fn j4_d1_a_child_notification_listener_is_a_gap_in_every_class() {
    let _serial = serial();
    let Some(work) = setup("d1-listener") else {
        return;
    };
    let helper = work.helper_s();
    let hidden = work.path("hidden");
    let seen = work.path("seen");
    let (reports, observed) = observe(&work, &[&helper, "listener", &hidden, &seen]);

    let listener = Report::find(&reports, "listener");
    assert!(
        listener.raw >= 0,
        "the listener was installed: {listener:?}"
    );
    let open = Report::find(&reports, "hidden_open");
    assert_eq!(open.errno, 0, "the continued openat ran: {open:?}");
    assert!(
        Path::new(&hidden).exists(),
        "and it created its file, with no trace stop for the observer"
    );
    assert!(
        !observed.primaries().iter().any(|p| p == &hidden),
        "the continued call is invisible to ptrace:\n  {}",
        observed.describe()
    );
    assert!(
        observed.primaries().iter().any(|p| p == &seen),
        "a call the listener does not take is still observed:\n  {}",
        observed.describe()
    );
    let gaps = observed.gaps_named("child_notification_listener");
    assert_eq!(
        gaps.len(),
        1,
        "a child's notification listener must be a named gap, not active coverage:\n  {}",
        observed.describe()
    );
    assert_eq!(
        gaps[0].0,
        OpSet::ALL,
        "any closed-set call may be continued"
    );
    assert_eq!(gaps[0].1, None, "how many calls it hid is not known");
}

/// D1, the named exclusion (integrator decision S3). A listener-less filter
/// of the child's own that fails a closed-set call (`SECCOMP_RET_ERRNO`
/// outranks `TRACE`) takes that call away before the observer's stop, but
/// the refused call had no effect. So its result is not observed and is not
/// a gap either: "a result the child's own filter refuses before the
/// observer's stop is not observed; it had no effect". (Passes on the base as
/// well: it pins the exclusion, so an inner Landlock/seccomp sandbox under
/// strict evidence is not stopped for it.)
#[test]
fn j4_d1_exclusion_a_filter_that_refuses_a_call_is_not_a_gap() {
    let _serial = serial();
    let Some(work) = setup("d1-errno") else {
        return;
    };
    refusing_filter_case(&work, "seccomp");
}

/// D1, the same exclusion through `prctl(PR_SET_SECCOMP)`, which cannot ask
/// for a listener at all.
#[test]
fn j4_d1_exclusion_holds_for_a_filter_installed_through_prctl() {
    let _serial = serial();
    let Some(work) = setup("d1-prctl") else {
        return;
    };
    refusing_filter_case(&work, "prctl");
}

fn refusing_filter_case(work: &Work, method: &str) {
    let helper = work.helper_s();
    let denied = work.path("denied");
    let seen = work.path("seen");
    let (reports, observed) = observe(work, &[&helper, "errno-filter", method, &denied, &seen]);

    assert_eq!(Report::find(&reports, "install").errno, 0, "{reports:?}");
    let mkdir = Report::find(&reports, "preempted_mkdir");
    assert_eq!(mkdir.errno, libc::EPERM, "the child's filter failed mkdir");
    assert!(!Path::new(&denied).exists(), "and it had no effect");
    assert_eq!(
        observed.of_op(ClosedOp::Mkdir).len(),
        0,
        "the refused call is not observed:\n  {}",
        observed.describe()
    );
    assert!(observed.primaries().iter().any(|p| p == &seen));
    let gaps: Vec<&TracerEvent> = observed
        .events
        .iter()
        .filter(|e| matches!(e, TracerEvent::Gap { .. }))
        .collect();
    assert!(
        gaps.is_empty(),
        "a refusal with no effect is the named exclusion, not a gap: {gaps:?}"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// D1, the extra stop. A child's own filter returning `SECCOMP_RET_TRACE`
/// reaches this tracer as a stop the narrowing filter did not ask for. On a
/// number outside the closed set it is continued untouched — never decoded,
/// never counted as loss, never labelled as a filter that is not the
/// observer's — and on a closed-set number it is the one stop the call has,
/// reported once.
#[test]
fn j4_d1_a_child_trace_request_is_continued_not_mislabelled() {
    let _serial = serial();
    let Some(work) = setup("d1-trace") else {
        return;
    };
    let helper = work.helper_s();
    let made = work.path("made");
    let (reports, observed) = observe(&work, &[&helper, "trace-request", &made]);

    assert_eq!(Report::find(&reports, "install").errno, 0, "{reports:?}");
    let getpid = Report::find(&reports, "getpid");
    assert!(getpid.raw > 0, "getpid ran after its stop: {getpid:?}");
    assert_eq!(Report::find(&reports, "mkdir").errno, 0);
    let gaps: Vec<&TracerEvent> = observed
        .events
        .iter()
        .filter(|e| matches!(e, TracerEvent::Gap { .. }))
        .collect();
    assert!(
        gaps.is_empty(),
        "a stop the child's own filter asked for is not a loss:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.of_op(ClosedOp::Mkdir).len(),
        1,
        "the closed-set call it also traced is reported once:\n  {}",
        observed.describe()
    );
    assert!(observed.primaries().iter().any(|p| p == &made));
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// D1, the contained profiles: `tool` and `build` refuse a notification
/// listener outright (`EPERM`), whatever the high word of the argument, and
/// still let the child stack a plain filter.
#[test]
fn j4_d1_the_tool_baseline_refuses_a_notification_listener() {
    let _serial = serial();
    let Some(work) = setup("d1-tool") else {
        return;
    };
    let helper = work.helper_s();
    let mut run = launch_tool(&work, &[&helper, "tool-listener"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let listener = Report::find(&reports, "new_listener");
    assert_eq!(
        listener.errno,
        libc::EPERM,
        "the tool baseline must refuse a notification listener: {listener:?}"
    );
    assert_eq!(
        Report::find(&reports, "new_listener_high_word").errno,
        libc::EPERM
    );
    assert_eq!(Report::find(&reports, "plain_filter").errno, 0);
    assert!(
        observed
            .gaps_named("child_notification_listener")
            .is_empty(),
        "a refused listener hides nothing"
    );
}

// ===========================================================================
// D2: a call under another ABI in `none`
// ===========================================================================

/// D2. Without a containment baseline nothing refuses the i386 or x32 ABI,
/// so the narrowing filter must stop on them, and the observer — which
/// decodes only the native table — must record each one it cannot attribute
/// as a gap in every class, labelled foreign, never as a native result. A
/// call the kernel refused as nonexistent (`ENOSYS`, which is what x32 gets
/// on a kernel built without it) had no effect and is not a loss.
#[test]
fn j4_d2_a_foreign_abi_call_without_a_baseline_is_a_gap() {
    let _serial = serial();
    if !foreign_abis() {
        return;
    }
    let Some(work) = setup("d2-foreign") else {
        return;
    };
    let helper = work.helper_s();
    let i386 = work.path("by-i386");
    let x32 = work.path("by-x32");
    let native = work.path("native");
    let (reports, observed) = observe(&work, &[&helper, "foreign", &i386, &x32, &native]);

    let i386_open = Report::find(&reports, "i386_open");
    assert_eq!(i386_open.errno, 0, "the i386 open ran: {i386_open:?}");
    assert!(Path::new(&i386).exists(), "and created its file");
    let x32_open = Report::find(&reports, "x32_openat");
    let nonexistent = Report::find(&reports, "i386_no_such_call");
    assert_eq!(nonexistent.errno, libc::ENOSYS);
    assert_eq!(Report::find(&reports, "native_open").errno, 0);

    let named = observed.primaries();
    assert!(
        named.iter().any(|p| p == &native),
        "the native call is seen"
    );
    assert!(
        !named.iter().any(|p| p == &i386 || p == &x32),
        "a foreign call is never decoded from the x86_64 table: {named:?}"
    );
    // Every foreign call the kernel did not refuse as nonexistent.
    let expected: u64 = [i386_open, x32_open]
        .iter()
        .filter(|r| r.errno != libc::ENOSYS)
        .count() as u64;
    let gaps = observed.gaps_named("foreign_abi");
    assert!(
        !gaps.is_empty(),
        "a foreign-ABI call in `none` must be a gap, not silence:\n  {}",
        observed.describe()
    );
    for (ops, _) in &gaps {
        assert_eq!(*ops, OpSet::ALL, "a call nothing decoded may be any class");
    }
    let counted: u64 = gaps.iter().filter_map(|(_, count)| *count).sum();
    assert_eq!(
        counted,
        expected,
        "one per foreign call that ran; x32={x32_open:?}\n  {}",
        observed.describe()
    );
}

// ===========================================================================
// D6: critical facts behind a full lifecycle backlog
// ===========================================================================

/// D6. The outbox bounds lifecycle facts at a count. Checked before the
/// exemption for critical facts, that bound drops a target's `Exit` and a
/// `Gap` once the backlog is full. The budget is filled first here
/// — twenty thousand fork facts nobody reads, with the byte budget raised so
/// the count bound is the one reached — then the fixture causes a gap and
/// exits. Both must reach the consumer, the gap ahead of the exit.
#[test]
fn j4_d6_critical_facts_survive_a_full_lifecycle_backlog() {
    /// How long the observer may take to reap the fixture with twenty
    /// thousand facts ahead of its exit; past it, the account is read as it
    /// stands.
    const REAP_BOUND: Duration = Duration::from_secs(120);
    let _serial = serial();
    let Some(work) = setup("d6-backlog") else {
        return;
    };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "forks-then-trace", "20000"]);
    let target = run.pid;
    let tracer = attach(
        run.pid,
        TracerConfig {
            queue_bytes_max: 64 * 1024 * 1024,
            ..TracerConfig::default()
        },
    );
    run.release();
    // Nothing is read until the observer has reaped the fixture, so every
    // fact, the exit included, waits in the observer's own buffer. Its
    // stdout closes before its death is reported, hence the reap and not EOF.
    let reports = run.lines();
    let _ = common::within(REAP_BOUND, || {
        !Path::new(&format!("/proc/{target}")).exists()
    });
    std::thread::sleep(Duration::from_millis(500));
    let observed = collect(tracer, Duration::from_secs(300));
    println!(
        "d6: forked={} lifecycle_dropped={} emitted={} gaps={}",
        Report::find(&reports, "forked").raw,
        observed.summary.loss.lifecycle_dropped,
        observed.summary.emitted,
        observed.summary.gaps
    );

    assert!(Report::find(&reports, "forked").raw >= 20_000 - 10);
    assert_eq!(Report::find(&reports, "install").errno, 0);
    assert!(
        observed.summary.loss.lifecycle_dropped > 0,
        "the lifecycle budget must be full before the critical facts: {:?}",
        observed.summary.loss
    );
    let exit = observed.events.iter().position(|e| {
        matches!(e, TracerEvent::Exit { pid, status, .. }
            if *pid == target && libc::WIFEXITED(*status) && libc::WEXITSTATUS(*status) == 0)
    });
    let gap = observed.events.iter().position(|e| {
        matches!(e, TracerEvent::Gap { reason, .. } if *reason == GapReason::UnexpectedTraceStop)
    });
    let dropped_facts: Vec<&TracerEvent> = observed
        .events
        .iter()
        .filter(|e| {
            matches!(e, TracerEvent::Gap { reason, ops, .. }
                if *reason == GapReason::LifecycleDropped && !ops.is_empty())
        })
        .collect();
    assert!(
        exit.is_some(),
        "the target's exit must survive a full lifecycle backlog; dropped: {dropped_facts:?}"
    );
    assert!(
        gap.is_some(),
        "and so must a gap; dropped: {dropped_facts:?}"
    );
    assert!(gap < exit, "the gap is delivered ahead of what followed it");
    assert!(
        dropped_facts.is_empty(),
        "only bookkeeping facts may be dropped: {dropped_facts:?}"
    );
    assert!(matches!(
        observed.events.last(),
        Some(TracerEvent::Finished)
    ));
}

// ===========================================================================
// The same two defects, end to end, in a `none` receipt
// ===========================================================================

fn none_run(work: &Work, evidence: &str, argv: &[&str]) -> Run {
    let workspace = work.dir().join("workspace");
    std::fs::create_dir_all(&workspace).expect("the workspace");
    Jail::new()
        .expect("a private harness")
        .arg("run")
        .arg("--profile")
        .arg("none")
        .arg("--evidence")
        .arg(evidence)
        .arg("--workspace")
        .arg(&workspace)
        .trace()
        .control()
        .target(argv.iter().map(OsString::from))
        .run()
        .expect("the jail runs")
}

fn gap_reasons(receipt: &Value) -> Vec<String> {
    receipt["observer"]["gaps"]
        .as_array()
        .map(|gaps| {
            gaps.iter()
                .filter_map(|gap| gap["reason"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// D1 in a receipt: a `none` child with its own notification listener. The
/// receipt must not read `active`, and strict evidence stops the attempt.
#[test]
fn j4_d1_none_a_child_listener_degrades_the_receipt_and_strict_stops() {
    let _serial = serial();
    if !common::delegated_leaf() {
        return;
    }
    let Some(work) = setup("d1-none") else {
        return;
    };
    let helper = work.helper_s();
    let hidden = work.path("hidden");
    let seen = work.path("seen");
    let run = none_run(&work, "strict", &[&helper, "listener", &hidden, &seen]);
    let receipt = common::settled(&run);
    let reasons = gap_reasons(&receipt);
    assert!(
        reasons.iter().any(|r| r == "child_notification_listener"),
        "the receipt must name the listener gap: {:#}",
        receipt["coverage"]
    );
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
        assert_eq!(entry["observed_count"], Value::Null, "{class}");
    }
    assert_eq!(
        receipt["outcome"]["cause"], "evidence_loss",
        "strict evidence stops the attempt: {:#}",
        receipt["outcome"]
    );
}

/// D2 in a receipt: a `none` child making one i386 call, best-effort so the
/// run completes. Every audit class is degraded and says why.
#[test]
fn j4_d2_none_a_foreign_abi_call_degrades_the_receipt() {
    let _serial = serial();
    if !foreign_abis() || !common::delegated_leaf() {
        return;
    }
    let Some(work) = setup("d2-none") else {
        return;
    };
    let helper = work.helper_s();
    let i386 = work.path("by-i386");
    let x32 = work.path("by-x32");
    let native = work.path("native");
    let run = none_run(
        &work,
        "best-effort",
        &[&helper, "foreign", &i386, &x32, &native],
    );
    let receipt = common::settled(&run);
    assert!(Path::new(&i386).exists(), "the i386 call ran");
    // Best-effort: the loss is an error of the run, not a stop of the child.
    assert_eq!(
        receipt["outcome"]["kind"], "exited",
        "{:#}",
        receipt["outcome"]
    );
    assert_eq!(receipt["outcome"]["code"], 0, "{:#}", receipt["outcome"]);
    assert!(
        gap_reasons(&receipt).iter().any(|r| r == "foreign_abi"),
        "the receipt must name the foreign-ABI gap: {:#}",
        receipt["coverage"]
    );
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
    }
}
