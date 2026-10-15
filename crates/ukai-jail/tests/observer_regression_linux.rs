#![cfg(target_os = "linux")]
//! Regression tests for the Linux ptrace observer, adopted from an
//! independent review of its first version.
//!
//! Each one was written by a reviewer against the first version of the
//! module, and each either found a defect or survived a mutation the
//! module's own suite did not catch. They are kept in the reviewer's own
//! shape — build a C fixture, run it under `Tracer::attach`, compare what the
//! observer said with what the fixture said about itself — and the name of
//! each test carries the reviewer's number so the finding it stands for can
//! be traced back.
//!
//! Where a fix changed what the right answer is, the assertion is inverted
//! rather than deleted, and the doc comment says which defect it now pins.
//!
//! The fixture is `fixtures/observer_regression.c`, built and launched by
//! `common/observer.rs`.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::fd::AsRawFd as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// Measure live requested allocation bytes independently of the observer's own
// queue accounting. RSS includes thread stacks, allocator arenas and retained
// freed pages, so it cannot establish a live event-queue allocation bound.
struct CountingAllocator;
static LIVE_BYTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// SAFETY: every allocation operation is forwarded unchanged to System; the
// counter neither dereferences nor changes the returned allocation.
unsafe impl std::alloc::GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract for
        // `layout`, which is the contract `System.alloc` asks for.
        let ptr = unsafe { std::alloc::System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), std::sync::atomic::Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        // SAFETY: as in `alloc`, the caller's contract for `layout` is the
        // one `System.alloc_zeroed` asks for.
        let ptr = unsafe { std::alloc::System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), std::sync::atomic::Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: the caller passes a block this allocator returned, which
        // `System` allocated, with the layout it was allocated with.
        unsafe { std::alloc::System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), std::sync::atomic::Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        // SAFETY: the caller passes a block `System` allocated with `layout`
        // and a valid new size, which is `System.realloc`'s contract.
        let next = unsafe { std::alloc::System.realloc(ptr, layout, size) };
        if !next.is_null() {
            LIVE_BYTES.fetch_add(size, std::sync::atomic::Ordering::Relaxed);
            LIVE_BYTES.fetch_sub(layout.size(), std::sync::atomic::Ordering::Relaxed);
        }
        next
    }
}

use ukai_jail::platform::linux::clock;
use ukai_jail::platform::linux::identity;
use ukai_jail::platform::linux::tracer::{
    ClosedOp, GapReason, OpSet, TracerConfig, TracerEvent, narrowing_filter_bytes, start_ticks,
};

mod common;

#[cfg(target_arch = "x86_64")]
use common::observer::launch_tool;
use common::observer::{
    Fixture, Observed, Report, Work, attach, collect, launch, mkfifo, primary, serial,
    spawn_launcher,
};

static FIXTURE: Fixture = Fixture {
    name: "observer_regression",
    source: include_str!("fixtures/observer_regression.c"),
    pthread: true,
    filter: narrowing_filter_bytes,
};

/// Prepare a check. `None` means it skipped and must return.
fn setup(name: &str) -> Option<Work> {
    FIXTURE.setup(name, &[])
}

impl Observed {
    /// What the observer said, a line per event, with each path cut to 48
    /// bytes.
    fn describe(&self) -> String {
        self.events
            .iter()
            .map(|e| match e {
                TracerEvent::Syscall {
                    tid,
                    syscall,
                    args,
                    ret,
                    ..
                } => format!(
                    "Syscall{{{tid} {syscall} ret={ret} p1={:?} p2={:?} sock={:?}}}",
                    args.path.as_ref().map(|p| (
                        String::from_utf8_lossy(&p.bytes[..p.bytes.len().min(48)]).into_owned(),
                        p.complete
                    )),
                    args.path2.as_ref().map(|p| (
                        String::from_utf8_lossy(&p.bytes[..p.bytes.len().min(48)]).into_owned(),
                        p.complete
                    )),
                    args.sockaddr
                ),
                other => format!("{other:?}"),
            })
            .collect::<Vec<_>>()
            .join("\n  ")
    }
}

fn rss_kib() -> i64 {
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse()
                .unwrap_or(0);
        }
    }
    0
}

fn proc_state(pid: libc::pid_t) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("State:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// A cBPF program written straight out, for the tests that install a filter
/// the module did not produce.
fn filter_bytes(program: &[libc::sock_filter]) -> Vec<u8> {
    let mut out = Vec::new();
    for insn in program {
        out.extend_from_slice(&insn.code.to_le_bytes());
        out.push(insn.jt);
        out.push(insn.jf);
        out.extend_from_slice(&insn.k.to_le_bytes());
    }
    out
}

// =============================================================== the checks

/// R1: an interrupted-and-restarted covered call produces exactly one
/// result. The regression test for the `ERESTARTSYS` check, which a mutation
/// survived because nothing exercised it.
#[test]
fn r1_a_restarted_syscall_produces_exactly_one_result() {
    let _serial = serial();
    let Some(work) = setup("r1") else { return };
    let fifo = work.path("f");
    mkfifo(&fifo);
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "restart-fifo", &fifo]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let open = Report::find(&reports, "fifo_open");
    let signals = Report::find(&reports, "signals");
    assert!(
        signals.raw >= 1,
        "the fixture must actually have been interrupted"
    );
    let opens: Vec<&TracerEvent> = observed
        .of_op(ClosedOp::Open)
        .into_iter()
        .filter(|e| primary(e) == fifo)
        .collect();
    assert_eq!(
        opens.len(),
        1,
        "one call, one result:\n  {}",
        observed.describe()
    );
    let TracerEvent::Syscall { ret, .. } = opens[0] else {
        unreachable!()
    };
    assert_eq!(*ret, open.ret());
    assert!(observed.summary.restarts >= 1, "the restart was recognised");
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "a restart is not loss: {:?}",
        observed.summary.loss
    );
}

/// R2: SIGSTOP and SIGCONT during a covered call neither wedge the tracer nor
/// duplicate the result. The group-stop is told apart from an attach stop by
/// `PTRACE_GETSIGINFO` and preserved with `PTRACE_LISTEN`.
#[test]
fn r2_a_group_stop_during_a_covered_call_is_survived() {
    let _serial = serial();
    let Some(work) = setup("r2") else { return };
    let fifo = work.path("f");
    mkfifo(&fifo);
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "stopcont", &fifo]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let open = Report::find(&reports, "fifo_open");
    let opens: Vec<&TracerEvent> = observed
        .of_op(ClosedOp::Open)
        .into_iter()
        .filter(|e| primary(e) == fifo)
        .collect();
    assert_eq!(opens.len(), 1, "\n  {}", observed.describe());
    let TracerEvent::Syscall { ret, .. } = opens[0] else {
        unreachable!()
    };
    assert_eq!(*ret, open.ret());
    assert_eq!(observed.exits().len(), 1, "{:?}", observed.exits());
    assert_eq!(observed.summary.loss.restart_failed, 0);
}

/// R3: a tracee that is already stopped when the supervisor seizes it can
/// still be attached, and the observer keeps working after SIGCONT.
#[test]
fn r3_attaching_to_an_already_stopped_tracee_works() {
    let _serial = serial();
    let Some(work) = setup("r3") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "quick", &base]);
    std::thread::sleep(Duration::from_millis(300));
    run.signal(libc::SIGSTOP).expect("stop the launcher");
    std::thread::sleep(Duration::from_millis(200));
    let tracer = attach(run.pid, TracerConfig::default());
    run.signal(libc::SIGCONT).expect("continue the launcher");
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    Report::find(&reports, "quick");
    assert_eq!(observed.execs(), vec![run.pid]);
    assert_eq!(observed.of_op(ClosedOp::Open).len(), 1);
    assert_eq!(observed.exits(), vec![(run.pid, 0)]);
}

/// R4: a process that exits while a covered call is in flight yields a gap,
/// never a manufactured result, and still yields one exit with the real code.
#[test]
fn r4_an_exit_while_a_call_is_in_flight_is_a_gap_not_a_result() {
    let _serial = serial();
    let Some(work) = setup("r4") else { return };
    let fifo = work.path("f");
    mkfifo(&fifo);
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "die-inflight", &fifo, "5"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let _ = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let opens: Vec<&TracerEvent> = observed
        .of_op(ClosedOp::Open)
        .into_iter()
        .filter(|e| primary(e) == fifo)
        .collect();
    assert!(
        opens.is_empty(),
        "the blocked open never returned, so no result may exist:\n  {}",
        observed.describe()
    );
    assert!(
        observed.summary.loss.abandoned_entries >= 1,
        "the entry that can no longer return must be counted: {:?}",
        observed.summary.loss
    );
    assert!(
        observed.has_gap(GapReason::EntryAbandoned),
        "{:?}",
        observed.gaps()
    );
    let exits = observed.exits();
    assert_eq!(exits.len(), 1, "{exits:?}");
    assert_eq!(exits[0].0, run.pid);
    assert_eq!(libc::WEXITSTATUS(exits[0].1), 5);
}

/// R5: a fork burst keeps attribution — one `Fork`, one `Exec` and one `Exit`
/// per child, each with the child's own exit code.
#[test]
fn r5_a_fork_burst_keeps_attribution() {
    let _serial = serial();
    let Some(work) = setup("r5") else { return };
    const N: usize = 300;
    let helper = work.helper_s();
    let n = N.to_string();
    let mut run = launch(&work, &[&helper, "forkburst", &n, "/bin/true"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(180));

    assert_eq!(Report::find(&reports, "forkburst").raw, N as i64);
    let forks = observed.forks();
    assert_eq!(forks.len(), N, "one Fork per child");
    let children: std::collections::BTreeSet<libc::pid_t> = forks.iter().map(|(_, c)| *c).collect();
    assert_eq!(children.len(), N, "no child pid reported twice");
    assert_eq!(
        observed.execs().len(),
        N + 1,
        "the launcher plus every child"
    );
    let exits = observed.exits();
    assert_eq!(exits.len(), N + 1);
    for (pid, status) in &exits {
        assert!(libc::WIFEXITED(*status), "pid {pid} status {status}");
        assert_eq!(libc::WEXITSTATUS(*status), 0, "pid {pid}");
    }
    let exited: std::collections::BTreeSet<libc::pid_t> = exits.iter().map(|(p, _)| *p).collect();
    for child in &children {
        assert!(exited.contains(child), "child {child} never got an Exit");
    }
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// R6: pathname arguments that lie. Each case is a snapshot that says what it
/// is, never a path the kernel did not see. A pointer the kernel itself could
/// not read is the tracee's invalid argument, not a hole in coverage.
#[test]
fn r6_hostile_path_pointers_never_produce_a_confident_path() {
    let _serial = serial();
    for kind in ["edge", "nonul", "unmapped", "minus1", "null", "long"] {
        let Some(work) = setup(&format!("r6-{kind}")) else {
            return;
        };
        let helper = work.helper_s();
        let base = work.base();
        let mut run = launch(&work, &[&helper, "badpath", kind, &base]);
        let tracer = attach(run.pid, TracerConfig::default());
        run.release();
        let reports = run.lines();
        let observed = collect(tracer, Duration::from_secs(60));
        let fixture = Report::find(&reports, kind);
        let opens = observed.of_op(ClosedOp::Open);
        assert_eq!(opens.len(), 1, "{kind}: exactly one result");
        let TracerEvent::Syscall { ret, args, .. } = opens[0] else {
            unreachable!()
        };
        assert_eq!(
            *ret,
            fixture.ret(),
            "{kind}: the return must be the kernel's"
        );
        let snapshot = args.path.clone();
        match kind {
            "edge" => {
                let snapshot = snapshot.expect("a readable path");
                assert!(snapshot.complete, "{kind}: the whole path was readable");
                assert_eq!(String::from_utf8_lossy(&snapshot.bytes), fixture.path);
            }
            "nonul" | "long" => {
                let snapshot = snapshot.expect("a snapshot");
                assert!(
                    !snapshot.complete,
                    "{kind}: a truncated path declares itself"
                );
                assert!(snapshot.bytes.len() <= 4096);
            }
            "unmapped" | "minus1" => {
                let snapshot = snapshot.expect("a snapshot");
                assert!(!snapshot.complete);
                assert!(snapshot.bytes.is_empty(), "{kind}: {:?}", snapshot.bytes);
                assert_eq!(
                    fixture.errno,
                    libc::EFAULT,
                    "{kind}: the kernel refused it too"
                );
                assert_eq!(
                    observed.summary.argument_invalid, 1,
                    "{kind}: an argument the kernel itself rejected is not lost coverage"
                );
                assert_eq!(
                    observed.summary.loss.total(),
                    0,
                    "{kind}: {:?}",
                    observed.summary.loss
                );
                assert!(
                    !observed.has_gap(GapReason::PathUnreadable),
                    "{kind}: there was no covered operation to miss"
                );
            }
            "null" => assert!(snapshot.is_none(), "{kind}: a null pointer has no snapshot"),
            _ => unreachable!(),
        }
    }
}

/// R7: a `sockaddr` whose declared length lies. Only the family and whether
/// the whole address of that family was readable are kept: the address bytes
/// are read to decide exactly that and dropped, so a `sockaddr_in`
/// announced as 128 bytes cannot pull 112 bytes of unrelated tracee memory
/// into the observer.
#[test]
fn r7_a_lying_sockaddr_length_retains_only_the_family_it_names() {
    let _serial = serial();
    for kind in [
        "lie-long",
        "edge",
        "over-edge",
        "unmapped",
        "zero-len",
        "huge-len",
        "null-ptr",
    ] {
        let Some(work) = setup(&format!("r7-{kind}")) else {
            return;
        };
        let helper = work.helper_s();
        let mut run = launch(&work, &[&helper, "badsock", kind]);
        let tracer = attach(run.pid, TracerConfig::default());
        run.release();
        let reports = run.lines();
        let observed = collect(tracer, Duration::from_secs(60));
        let connects = observed.of_op(ClosedOp::Connect);
        assert_eq!(connects.len(), 1, "{kind}: one connect, one result");
        let TracerEvent::Syscall { ret, args, .. } = connects[0] else {
            unreachable!()
        };
        let fixture = Report::find(&reports, &kind.replace('-', "_"));
        assert_eq!(*ret, fixture.ret(), "{kind}: the kernel's return");
        let sockaddr = args.sockaddr.clone();
        if kind == "null-ptr" {
            assert!(sockaddr.is_none(), "{kind}: a null address has no snapshot");
            continue;
        }
        let sockaddr = sockaddr.expect("a snapshot");
        if kind == "zero-len" {
            // The kernel rejects a length under two; there is no family.
            assert_eq!(sockaddr.family, None, "{kind}");
            assert!(!sockaddr.complete, "{kind}");
            continue;
        }
        if kind == "unmapped" {
            // The family itself is in unreadable memory: named as loss, and
            // the kernel's EFAULT on the same pointer is not.
            assert_eq!(sockaddr.family, None, "{kind}");
            assert!(!sockaddr.complete, "{kind}");
            continue;
        }
        assert_eq!(
            sockaddr.family,
            Some(libc::AF_INET as u16),
            "{kind}: the family is read from the address the caller passed"
        );
        if kind == "lie-long" || kind == "huge-len" {
            assert!(
                sockaddr.complete,
                "{kind}: the whole sockaddr_in was readable despite the lying claim"
            );
        }
    }
}

/// R8: `mknodat` and `truncate` are inside the closed set as of jail-v1 §11.2,
/// and are now named. On x86_64, the fixture additionally exercises i386 and
/// x32 calls to verify that foreign ABI operations are never named as native.
#[test]
fn r8_the_grown_closed_set_names_mknod_and_truncate_but_never_another_abi() {
    let _serial = serial();
    let Some(work) = setup("r8") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "outside", &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let paths: Vec<String> = observed.syscalls().iter().map(|e| primary(e)).collect();
    let mknod = Report::find(&reports, "mknodat");
    let truncate = Report::find(&reports, "truncate");
    assert_eq!(mknod.errno, 0, "the fixture's mknodat must succeed");
    assert_eq!(truncate.errno, 0);
    assert!(
        paths.iter().any(|p| p.ends_with("by-mknod")),
        "mknodat is a directory-entry creation and is inside the set: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.ends_with("by-truncate")),
        "truncate names a pathname and is inside the set: {paths:?}"
    );
    assert_eq!(observed.of_op(ClosedOp::Mknod).len(), 1);
    assert_eq!(observed.of_op(ClosedOp::Truncate).len(), 1);
    #[cfg(target_arch = "x86_64")]
    {
        assert!(
            !paths.iter().any(|p| p.ends_with("by-int80")),
            "an i386 open is outside the native ABI and must not be named: {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p.ends_with("by-x32")),
            "an x32 openat carries a number from another table: {paths:?}"
        );
    }
}

/// R9: `open_how` structures of every awkward size. Every result the observer
/// does deliver carries the kernel's own return, and a size it cannot decode
/// is never delivered as a covered open.
#[test]
fn r9_open_how_sizes_are_decoded_or_declared_unavailable() {
    let _serial = serial();
    let Some(work) = setup("r9") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "openhow", &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    for event in observed.of_op(ClosedOp::Open) {
        let TracerEvent::Syscall { args, ret, .. } = event else {
            unreachable!()
        };
        let path = primary(event);
        assert!(
            args.flags.is_some(),
            "a delivered open must have had its flags decoded: {path}"
        );
        if let Some(fixture) = reports.iter().find(|r| r.path == path) {
            assert_eq!(*ret, fixture.ret(), "path {path}");
        }
    }
    // Sizes 0, 8 and 16 are below the structure the kernel defines, so it
    // rejects them and there was no covered operation to classify.
    for label in ["size_0", "size_8", "size_16"] {
        assert_eq!(Report::find(&reports, label).errno, libc::EINVAL, "{label}");
    }
    assert!(
        observed.summary.argument_invalid >= 3,
        "{:?}",
        observed.summary
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// R10: §11.4 budgets bytes, not events. Sixteen thousand two-path renames
/// must not make the observer hold more than the budget.
#[test]
fn r10_the_queue_bound_is_the_four_mib_of_the_spec() {
    let _serial = serial();
    let Some(work) = setup("r10") else { return };
    const N: u64 = 16_000;
    let helper = work.helper_s();
    let base = work.base();
    let n = N.to_string();
    let rss_before = rss_kib();
    let allocated_before = LIVE_BYTES.load(std::sync::atomic::Ordering::Relaxed);
    let mut run = launch(&work, &[&helper, "bigpaths", &n, &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    // Deliberately do not read the queue while the fixture runs.
    let mut line = String::new();
    run.output.read_line(&mut line).expect("the fixture report");
    let peak = rss_kib();
    let allocated_delta = LIVE_BYTES
        .load(std::sync::atomic::Ordering::Relaxed)
        .saturating_sub(allocated_before);
    let observed = collect(tracer, Duration::from_secs(120));
    let delta_mib = (peak - rss_before) as f64 / 1024.0;
    println!(
        "r10: {N} two-path events queued, supervisor RSS delta {delta_mib:.2} MiB, \
         live allocations {allocated_delta} bytes, observer peak {:.2} MiB, dropped {}",
        observed.summary.queue_bytes_peak as f64 / (1024.0 * 1024.0),
        observed.summary.loss.queue_dropped
    );
    assert_eq!(
        observed.summary.ops.get(ClosedOp::Rename),
        N,
        "every call was still observed"
    );
    assert!(
        observed.summary.queue_bytes_peak <= TracerConfig::default().queue_bytes_max,
        "the observer's own accounting must stay inside the budget: {} bytes",
        observed.summary.queue_bytes_peak
    );
    assert!(
        allocated_delta < 4 * 1024 * 1024,
        "jail-v1 §11.4 budgets a 4 MiB user-space event queue; live allocations grew by \
         {allocated_delta} bytes"
    );
    assert!(
        observed.summary.loss.queue_dropped > 0,
        "with a byte budget this workload must lose results rather than memory"
    );
}

/// R11: an untraced child that outlives the traced tree — bubblewrap, in the
/// real tree — still has its exit reported. It has exactly one route.
///
/// Bubblewrap is the launcher's ancestor, and the test builds it that way:
/// an untraced `sh` is this process's child, the launcher is its child, and
/// the `sh` outlives the traced tree by two seconds before exiting 5. The
/// untraced child is not the launcher's *sibling*: a tracer that waited for
/// every child the process had when it attached let a process substitution
/// the supervisor inherited from the shell that exec'd it hold the observer
/// open, and counted it as lost. A sibling is not the tracer's to wait for
/// (`j5_tracer_foreign_child_linux`); the child it reached the launcher
/// through is, and this pins that exit's route.
#[test]
fn r11_a_late_untraced_child_exit_is_still_reported() {
    let _serial = serial();
    let Some(work) = setup("r11") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let filter = work.filter.to_string_lossy().into_owned();
    // A background job's stdin is `/dev/null` before its own redirections
    // apply, so the release pipe is passed on fd 3.
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        r#"exec 3<&0; "$@" <&3 3<&- & wait $!; sleep 2; exit 5"#,
        "sh",
        &helper,
        "launch",
        &filter,
        &helper,
        "quick",
        &base,
    ]);
    let mut run = spawn_launcher(command);
    let backend = run.pid;
    let launcher = ukai_jail::platform::linux::tracer::children(backend)
        .into_iter()
        .find(|pid| {
            ukai_jail::platform::linux::tracer::cmdline(*pid)
                .is_some_and(|argv| argv.get(1).map(Vec::as_slice) == Some(b"launch".as_slice()))
        })
        .unwrap_or_else(|| panic!("no launcher under the untraced sh {backend}"));
    let tracer = attach(launcher, TracerConfig::default());
    run.release();
    let _ = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));
    println!(
        "r11: untraced exits {:?}, backend state after finish {:?}",
        observed.untraced_exits(),
        proc_state(backend)
    );
    let exit = observed
        .untraced_exits()
        .into_iter()
        .find(|(p, _)| *p == backend)
        .unwrap_or_else(|| {
            panic!(
                "the exit of the untraced child {backend}, which the launcher descends \
                 through, must reach the supervisor, which was told not to wait for its own \
                 children while a tracer is attached: {:?}",
                observed.untraced_exits()
            )
        });
    assert!(
        libc::WIFEXITED(exit.1) && libc::WEXITSTATUS(exit.1) == 5,
        "its own status: {:#x}",
        exit.1
    );
    assert!(
        observed.summary.unreaped_children.is_empty(),
        "{:?}",
        observed.summary.unreaped_children
    );
}

/// R12: `finish` returns even when a tracee is alive and will not die, and
/// says what it had to do about it. `Drop` is the same path, so a panicking
/// consumer cannot be wedged either.
#[test]
fn r12_finish_returns_even_when_a_tracee_will_not_die() {
    let _serial = serial();
    let Some(work) = setup("r12") else { return };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "sleep-forever"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let mut line = String::new();
    run.output
        .read_line(&mut line)
        .expect("the sleeping report");
    let pid = run.pid;

    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let started = Instant::now();
    let joiner = std::thread::spawn(move || {
        let summary = tracer.finish_within(Duration::from_millis(300));
        let _ = tx.send(());
        summary
    });
    let returned = rx.recv_timeout(Duration::from_secs(20)).is_ok();
    if !returned {
        // The rescue for a `finish` that never returned, so the joiner can.
        // ESRCH means the tracee is gone already.
        match run.signal(libc::SIGKILL) {
            Err(error) if error.raw_os_error() != Some(libc::ESRCH) => {
                panic!("kill the tracee: {error}")
            }
            _ => {}
        }
    }
    let summary = joiner.join().expect("the joining thread");
    println!(
        "r12: finish_within returned after {:?}, abandoned={} unreaped={:?}",
        started.elapsed(),
        summary.loss.abandoned_tracees,
        summary.unreaped_children
    );
    assert!(returned, "finish must always return");
    assert!(
        summary.loss.abandoned_tracees >= 1,
        "a tree that had to be killed is loss, and is counted: {:?}",
        summary.loss
    );
    common::eventually(
        "the tracee that would not die to be killed, not left stopped",
        common::STEP_BOUND,
        || !std::path::Path::new(&format!("/proc/{pid}")).exists(),
    );
}

/// R13: a consumer that never reads costs one bounded stall, not one per
/// event, and every call is still observed.
#[test]
fn r13_a_stalled_consumer_stalls_the_tree_by_a_bounded_amount() {
    let _serial = serial();
    let Some(work) = setup("r13") else { return };
    const N: u64 = 20_000;
    let helper = work.helper_s();
    let base = work.base();
    let n = N.to_string();
    let untraced_start = Instant::now();
    let status = Command::new(&work.helper)
        .args(["bigpaths", &n, &base])
        .stdout(Stdio::null())
        .status()
        .expect("untraced run");
    let untraced = untraced_start.elapsed();
    assert!(status.success());

    let mut run = launch(&work, &[&helper, "bigpaths", &n, &base]);
    let tracer = attach(
        run.pid,
        TracerConfig {
            queue_max: 8,
            ..TracerConfig::default()
        },
    );
    let started = Instant::now();
    run.release();
    let mut line = String::new();
    run.output.read_line(&mut line).expect("the fixture report");
    let stalled = started.elapsed();
    let observed = collect(tracer, Duration::from_secs(120));
    println!(
        "r13: untraced {untraced:?}; traced with a consumer that never reads {stalled:?}; \
         dropped={} emitted={}",
        observed.summary.loss.queue_dropped, observed.summary.emitted
    );
    assert_eq!(
        observed.summary.ops.get(ClosedOp::Rename),
        N,
        "every call still observed"
    );
    assert!(
        stalled < Duration::from_secs(10),
        "a consumer that never reads must cost one bounded stall, not one per event"
    );
}

/// R17: a filter that traces a number outside the closed set. The tracer says
/// the filter is not its own instead of guessing, and does not wedge the
/// tracee.
///
/// The tracer tells whose a stop is by its trace data: a stop
/// carrying the narrowing filter's own data on a number it never traces
/// means the installed program is not the observer's, while one with other
/// data was asked for by another filter (a child's own `SECCOMP_RET_TRACE`)
/// and is continued untouched. This filter therefore carries the observer's
/// data, which is the case this test pins; the other is
/// `observer_j4_linux::j4_d1_a_child_trace_request_is_continued_not_mislabelled`.
#[test]
fn r17_a_foreign_filter_is_named_not_guessed() {
    let _serial = serial();
    let Some(work) = setup("r17") else { return };
    let program = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 2,
            k: if cfg!(target_arch = "aarch64") {
                0xc000_00b7
            } else {
                0xc000_003e
            },
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: u32::try_from(libc::SYS_close).unwrap(),
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff_0000,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7ff0_0000 | u32::from(ukai_jail::platform::linux::tracer::NARROWING_TRACE_DATA),
        },
    ];
    let foreign = work.path("foreign.bin");
    std::fs::write(&foreign, filter_bytes(&program)).expect("write the foreign filter");
    let helper = work.helper_s();
    let mut command = Command::new(&work.helper);
    command
        .arg("launch")
        .arg(&foreign)
        .args([&helper, "closes", "50"]);
    let mut run = spawn_launcher(command);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    Report::find(&reports, "closes");
    assert!(
        observed.summary.loss.unexpected_trace_stops >= 50,
        "every stop for a number outside the set is named: {:?}",
        observed.summary.loss
    );
    assert!(observed.has_gap(GapReason::UnexpectedTraceStop));
    assert_eq!(observed.of_op(ClosedOp::Open).len(), 0, "nothing invented");
}

/// R18: `EINPROGRESS` is the raw return the caller saw, not a completed
/// connection.
#[test]
fn r18_einprogress_is_the_raw_return() {
    let _serial = serial();
    let Some(work) = setup("r18") else { return };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "inprogress"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));
    let fixture = Report::find(&reports, "inprogress");
    let connects = observed.of_op(ClosedOp::Connect);
    assert_eq!(connects.len(), 1);
    let TracerEvent::Syscall { ret, .. } = connects[0] else {
        unreachable!()
    };
    assert_eq!(*ret, fixture.ret());
    assert_eq!(fixture.errno, libc::EINPROGRESS, "the fixture's own view");
}

/// R19: the two paths of a two-path call are independent evidence, and a
/// pointer the kernel also rejected is the tracee's argument, not lost
/// coverage.
#[test]
fn r19_two_paths_are_independent_evidence() {
    let _serial = serial();
    let Some(work) = setup("r19") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "twopath", &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let renames = observed.of_op(ClosedOp::Rename);
    assert_eq!(renames.len(), 2, "\n  {}", observed.describe());
    for (i, event) in renames.iter().enumerate() {
        let TracerEvent::Syscall { args, ret, .. } = event else {
            unreachable!()
        };
        assert_eq!(*ret, reports[i].ret(), "case {i}");
        let (good, bad) = if i == 0 {
            (args.path.clone().unwrap(), args.path2.clone().unwrap())
        } else {
            (args.path2.clone().unwrap(), args.path.clone().unwrap())
        };
        assert!(good.complete, "case {i}: the readable path is complete");
        assert!(!bad.complete, "case {i}: the faulting path is not");
        assert!(bad.bytes.is_empty(), "case {i}: {:?}", bad.bytes);
    }
    assert!(
        observed.summary.argument_invalid >= 2,
        "the kernel rejected both pointers too: {:?}",
        observed.summary
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// R20: every task the tracer tracked is accounted for at the end. A thread
/// the kernel destroys as part of another thread's `execve` is never reported
/// by the kernel, so it is counted rather than left unexplained.
#[test]
fn r20_a_non_leader_exec_accounts_for_every_thread() {
    let _serial = serial();
    let Some(work) = setup("r20") else { return };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "threads-exec", "/bin/true"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let _ = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    assert_eq!(observed.exits(), vec![(run.pid, 0)], "one process death");
    println!(
        "r20: tracees={} reaped={} destroyed_by_exec={}",
        observed.summary.tracees,
        observed.summary.reaped_tasks,
        observed.summary.tasks_destroyed_by_exec
    );
    assert_eq!(
        observed.summary.tracees,
        observed.summary.reaped_tasks + observed.summary.tasks_destroyed_by_exec,
        "every task the tracer tracked must be accounted for at the end"
    );
    assert!(observed.summary.tasks_destroyed_by_exec >= 1);
}

/// R21: the product's shape — the `tool` enforcement baseline installed
/// first, the observer's narrowing filter second. The baseline denies the ABI
/// the observer cannot name, and the calls the observer does name still work
/// and are still reported.
#[test]
#[cfg(target_arch = "x86_64")]
fn r21_the_tool_baseline_denies_the_abi_the_observer_cannot_name() {
    let _serial = serial();
    let Some(work) = setup("r21") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let mut run = launch_tool(&work, &[&helper, "abi", &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let int80 = Report::find(&reports, "int80");
    let native = Report::find(&reports, "native");
    let mknod = Report::find(&reports, "mknodat");
    println!(
        "r21: int80 errno={} native errno={} mknodat errno={}",
        int80.errno, native.errno, mknod.errno
    );
    assert_eq!(
        int80.errno,
        libc::EPERM,
        "the tool baseline must deny the i386 ABI the observer cannot name"
    );
    assert!(
        !std::path::Path::new(&work.path("abi-int80")).exists(),
        "and it must not have created anything"
    );
    assert_eq!(native.errno, 0, "the native call still works");
    assert_eq!(observed.of_op(ClosedOp::Open).len(), 1, "and is observed");
    assert_eq!(mknod.errno, 0, "mknodat is not denied by the tool baseline");
    assert_eq!(
        observed.of_op(ClosedOp::Mknod).len(),
        1,
        "so the closed set is what must name it: {}",
        observed.describe()
    );
}

/// R22: a read-only open costs one stop and produces no event.
#[test]
fn r22_a_read_only_open_costs_one_stop_and_no_event() {
    let _serial = serial();
    let Some(work) = setup("r22") else { return };
    const N: u64 = 5000;
    let target = work.path("readable");
    std::fs::write(&target, b"x").expect("create the file");
    let helper = work.helper_s();
    let n = N.to_string();
    let mut run = launch(&work, &[&helper, "rdonly", &n, &target]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(180));

    assert_eq!(Report::find(&reports, "rdonly").raw, N as i64);
    assert_eq!(observed.of_op(ClosedOp::Open).len(), 0, "no event");
    assert_eq!(observed.summary.ops.total(), 0);
    assert!(observed.summary.filtered_readonly_opens >= N);
    assert!(
        observed.summary.stops < 2 * N,
        "a read-only open must cost the seccomp stop only: {} stops for {N} opens",
        observed.summary.stops
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// R23: `Fork.parent` is the thread group, so a consumer can join it with
/// every other event's `pid`, and the forking thread is named separately.
#[test]
fn r23_fork_names_the_thread_group_and_the_thread_that_forked() {
    let _serial = serial();
    let Some(work) = setup("r23") else { return };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "worker-fork", "/bin/true"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let leader = Report::find(&reports, "leader_pid").raw as libc::pid_t;
    let worker = Report::find(&reports, "worker_tid").raw as libc::pid_t;
    let child = Report::find(&reports, "child_pid").raw as libc::pid_t;
    assert_ne!(
        worker, leader,
        "the fork really was made by a worker thread"
    );
    let event = observed
        .events
        .iter()
        .find_map(|e| match e {
            TracerEvent::Fork {
                parent,
                parent_tid,
                child: c,
                is_thread,
                child_start_ticks,
                ..
            } if *c == child => Some((*parent, *parent_tid, *is_thread, *child_start_ticks)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no Fork for {child}: {:?}", observed.forks()));
    let (parent, parent_tid, is_thread, start_ticks) = event;
    assert_eq!(
        parent, leader,
        "Fork.parent is the thread group, like every other pid"
    );
    assert_eq!(
        parent_tid, worker,
        "and the forking thread is named on its own"
    );
    assert!(!is_thread, "a fork child is a process, not a thread");
    assert!(
        start_ticks.is_some(),
        "a birth identity tells recycled pids apart"
    );
    // The thread the worker-fork fixture created is reported as a thread.
    let threads: Vec<bool> = observed
        .events
        .iter()
        .filter_map(|e| match e {
            TracerEvent::Fork { is_thread, .. } => Some(*is_thread),
            _ => None,
        })
        .collect();
    assert!(
        threads.contains(&true),
        "the pthread_create is a thread clone: {threads:?}"
    );
}

/// R24: when the queue drops results, the consumer still receives the
/// lifecycle facts, and the gap names the classes it cost.
#[test]
fn r24_a_queue_gap_names_what_it_lost_and_never_swallows_the_exit() {
    let _serial = serial();
    let Some(work) = setup("r24") else { return };
    let helper = work.helper_s();
    let a = work.path("a");
    let b = work.path("b");
    let mut run = launch(&work, &[&helper, "two-threads", "500", &a, &b]);
    let tracer = attach(
        run.pid,
        TracerConfig {
            queue_max: 1,
            ..TracerConfig::default()
        },
    );
    run.release();
    let _ = run.lines();
    std::thread::sleep(Duration::from_millis(1500));
    let observed = collect(tracer, Duration::from_secs(60));

    println!(
        "r24: dropped={} observed={} delivered={} exits={:?} gaps={:?}",
        observed.summary.loss.queue_dropped,
        observed.summary.ops.total(),
        observed.of_op(ClosedOp::Open).len(),
        observed.exits(),
        observed.gaps()
    );
    assert!(
        observed.summary.loss.queue_dropped > 0,
        "the queue must overflow"
    );
    assert_eq!(
        observed.exits().len(),
        1,
        "a supervisor must never lose the exit status it exists to report"
    );
    let queue_gaps: Vec<(GapReason, OpSet, Option<u64>)> = observed
        .gaps()
        .into_iter()
        .filter(|(reason, _, _)| *reason == GapReason::QueueFull)
        .collect();
    assert!(!queue_gaps.is_empty(), "the loss must be reported as a gap");
    for (_, ops, count) in &queue_gaps {
        assert!(
            count.is_some(),
            "the count of dropped events is known exactly"
        );
        assert!(
            ops.contains(ClosedOp::Open),
            "jail-v1 §11.4: a gap names the affected classes, and these were opens"
        );
    }
    let counted: u64 = queue_gaps.iter().filter_map(|(_, _, c)| *c).sum();
    assert_eq!(counted, observed.summary.loss.queue_dropped);
    assert!(
        observed
            .events
            .iter()
            .any(|e| matches!(e, TracerEvent::Finished))
    );
}

/// R25: `args.path` is the directory entry the call creates on every row,
/// including `symlink`, whose target is an opaque string the kernel stores
/// without resolving it.
#[test]
fn r25_symlink_reports_the_link_it_creates_as_its_primary_path() {
    let _serial = serial();
    let Some(work) = setup("r25") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "symlink", &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let fixture = Report::find(&reports, "symlink");
    assert_eq!(fixture.errno, 0);
    let events = observed.of_op(ClosedOp::Symlink);
    assert_eq!(events.len(), 1);
    let TracerEvent::Syscall { args, .. } = events[0] else {
        unreachable!()
    };
    let path = String::from_utf8_lossy(&args.path.as_ref().expect("a link").bytes).into_owned();
    let target =
        String::from_utf8_lossy(&args.path2.as_ref().expect("a target").bytes).into_owned();
    assert!(
        path.ends_with("/the-link"),
        "args.path is the entry the call creates, as on every other row: {path}"
    );
    assert_eq!(
        target, "THE-TARGET",
        "and the string the kernel stores without resolving is args.path2"
    );
    assert_eq!(
        args.dirfd2, None,
        "a stored string is resolved against nothing"
    );
}

/// R26: a tracee cannot decide how much loss the observer records. Five
/// thousand calls with a pointer the kernel itself rejects are five thousand
/// invalid arguments, not five thousand holes in coverage — which under
/// strict evidence would let an untrusted child stop its own attempt.
#[test]
fn r26_a_tracee_cannot_manufacture_the_observers_loss() {
    let _serial = serial();
    let Some(work) = setup("r26") else { return };
    const N: u64 = 5000;
    let helper = work.helper_s();
    let n = N.to_string();
    let mut run = launch(&work, &[&helper, "unreadable", &n]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(180));

    assert_eq!(Report::find(&reports, "unreadable").raw, N as i64);
    assert_eq!(
        observed.summary.argument_invalid, N,
        "each call had an argument the kernel rejected too"
    );
    assert_eq!(
        observed.summary.loss.path_unreadable, 0,
        "none of it is the observer's coverage"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "and none of it may stop a strict-evidence attempt: {:?}",
        observed.summary.loss
    );
    assert_eq!(
        observed.summary.ops.get(ClosedOp::Open),
        N,
        "every result is still reported"
    );
}

/// R27: a seccomp stop whose `nr` belongs to another architecture's table is
/// never labelled from this one. i386 42 is `pipe`; x86_64 42 is `connect`.
///
/// Such a stop is labelled foreign (`foreign_abi`), not
/// `unexpected_trace_stop`: the narrowing filter itself stops on every
/// foreign call, so the stop is expected and the gap says what it is.
#[test]
#[cfg(target_arch = "x86_64")]
fn r27_a_foreign_architecture_stop_is_never_labelled_from_the_x86_64_table() {
    let _serial = serial();
    let Some(work) = setup("r27") else { return };
    let program = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 42,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff_0000,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7ff0_0000,
        },
    ];
    let blind = work.path("archblind.bin");
    std::fs::write(&blind, filter_bytes(&program)).expect("write the filter");
    let helper = work.helper_s();
    let mut command = Command::new(&work.helper);
    command
        .arg("launch")
        .arg(&blind)
        .args([&helper, "i386-pipe"]);
    let mut run = spawn_launcher(command);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    Report::find(&reports, "i386_pipe");
    assert_eq!(
        observed.of_op(ClosedOp::Connect).len(),
        0,
        "an i386 `pipe` must never be reported as an x86_64 `connect`:\n  {}",
        observed.describe()
    );
    assert!(
        observed.summary.loss.foreign_abi >= 1,
        "the stop from another architecture must be a named gap: {:?}",
        observed.summary.loss
    );
    assert!(observed.has_gap(GapReason::ForeignAbi));
    assert_eq!(
        observed.summary.loss.unexpected_trace_stops, 0,
        "and it is labelled foreign, not as a filter that is not the observer's"
    );
}

/// R28: two threads of one process making concurrent covered calls. Each
/// result carries the path its own thread asked for, which is what the
/// per-thread pairing key is for.
#[test]
fn r28_concurrent_threads_pair_their_own_entries_and_exits() {
    let _serial = serial();
    let Some(work) = setup("r28") else { return };
    const N: u64 = 2000;
    let leader_path = work.path("by-leader");
    let worker_path = work.path("by-worker");
    let helper = work.helper_s();
    let n = N.to_string();
    let mut run = launch(
        &work,
        &[&helper, "two-threads", &n, &leader_path, &worker_path],
    );
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let _ = run.lines();
    let observed = collect(tracer, Duration::from_secs(300));

    let mut by_tid: std::collections::BTreeMap<
        libc::pid_t,
        std::collections::BTreeMap<String, u64>,
    > = std::collections::BTreeMap::new();
    for event in observed.of_op(ClosedOp::Open) {
        if let TracerEvent::Syscall { tid, .. } = event {
            *by_tid
                .entry(*tid)
                .or_default()
                .entry(primary(event))
                .or_default() += 1;
        }
    }
    assert_eq!(
        observed.summary.ops.get(ClosedOp::Open),
        2 * N,
        "both threads' calls are results"
    );
    assert_eq!(
        by_tid.len(),
        2,
        "exactly two threads made covered calls: {by_tid:?}"
    );
    for (tid, paths) in &by_tid {
        assert_eq!(
            paths.len(),
            1,
            "thread {tid} made calls on one pathname only, so its results must all \
             carry that pathname: {paths:?}"
        );
        assert_eq!(*paths.values().next().expect("one path"), N, "thread {tid}");
    }
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// R29: `PTRACE_O_EXITKILL`. A supervisor that dies must take its traced tree
/// with it; a mutation that dropped the option survived until this test.
#[test]
fn r29_a_dead_supervisor_kills_its_traced_tree() {
    let _serial = serial();
    if FIXTURE.built().is_none() {
        return;
    }
    let dir = common::private_tempdir();
    let pid_file = dir.path().join("pid");
    // The helper ends with `_exit`, so it never reports; the pid file it
    // writes is what proves it ran.
    let status = common::helper_command("exitkill_child_supervisor")
        .env("UKAI_REGRESS_EXITKILL", &pid_file)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("run the child supervisor");
    assert!(status.success(), "the child supervisor: {status:?}");
    let raw = std::fs::read_to_string(&pid_file).expect("the child wrote the tracee pid");
    let (tracee, birth) = raw.trim().split_once(' ').expect("a pid and its birth");
    let tracee: libc::pid_t = tracee.parse().expect("a pid");
    let birth: u64 = birth.parse().expect("a birth");
    // The tracee is not this process's child, so its number is free for
    // anyone once it is reaped: the pid with the birth the child recorded is
    // the tracee, and a pid alone is not.
    let still_there = || start_ticks(tracee) == Some(birth);
    let alive = !common::within(common::STEP_BOUND, || !still_there());
    if alive {
        // The rescue, through a pidfd checked against that birth after it
        // was opened, so it reaches the tracee or nothing.
        if let Ok(pidfd) = identity::pidfd_open(tracee)
            && still_there()
        {
            let _ = identity::pidfd_send_signal(pidfd.as_raw_fd(), libc::SIGKILL);
        }
    }
    assert!(
        !alive,
        "the supervisor died and its tracee {tracee} is still running: \
         PTRACE_O_EXITKILL is what makes a dead supervisor take the tree with it"
    );
}

/// The child half of `r29`: a supervisor that dies without cleaning up.
#[test]
#[ignore = "a helper process of r29_a_dead_supervisor_kills_its_traced_tree"]
fn exitkill_child_supervisor() {
    if !common::running_helper("exitkill_child_supervisor") {
        return;
    }
    let _serial = serial();
    let pid_file =
        std::env::var_os("UKAI_REGRESS_EXITKILL").expect("the parent names the pid file");
    // No working directory: nothing this half leaves could be removed.
    let Some(built) = FIXTURE.built() else {
        return;
    };
    let mut command = built.launcher();
    command.arg(&built.helper).arg("sleep-forever");
    let mut run = spawn_launcher(command);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let mut line = String::new();
    run.output.read_line(&mut line).expect("the sleeping line");
    let birth = start_ticks(run.pid).expect("the tracee's birth");
    std::fs::write(&pid_file, format!("{} {birth}", run.pid)).expect("write the pid");
    std::mem::forget(tracer);
    std::mem::forget(run);
    // SAFETY: `_exit` ends the process without running any destructor, which
    // is the point: this half is a supervisor that dies.
    unsafe { libc::_exit(0) };
}

/// R30: repeated attach and finish cycles leave no thread, no descriptor and
/// no zombie behind.
#[test]
fn r30_repeated_attach_and_finish_leaks_nothing() {
    let _serial = serial();
    let Some(built) = FIXTURE.built() else {
        return;
    };
    let dir = common::private_tempdir();

    let count = |path: &str| std::fs::read_dir(path).map(Iterator::count).unwrap_or(0);
    let mut baseline = (0usize, 0usize);
    for round in 0..21u32 {
        if round == 1 {
            std::thread::sleep(Duration::from_millis(100));
            baseline = (count("/proc/self/task"), count("/proc/self/fd"));
            println!(
                "r30: baseline after warm-up threads={} fds={}",
                baseline.0, baseline.1
            );
        }
        let target = dir.path().join(format!("t{round}"));
        let mut child = built
            .launcher()
            .arg(&built.helper)
            .arg("quick")
            .arg(&target)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn");
        let pid = child.id() as libc::pid_t;
        let mut release = child.stdin.take().expect("stdin");
        let mut out = BufReader::new(child.stdout.take().expect("stdout"));
        drop(child);
        let mut ready = String::new();
        out.read_line(&mut ready)
            .expect("the launcher announces itself");
        assert!(
            ready.starts_with("ready"),
            "unexpected first line {ready:?}"
        );
        let tracer = attach(pid, TracerConfig::default());
        release.write_all(b"g").expect("release");
        release.flush().expect("flush");
        let mut line = String::new();
        let _ = out.read_line(&mut line);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut saw_exit = false;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match tracer.events().recv_timeout(left) {
                Ok(TracerEvent::Finished) => break,
                Ok(TracerEvent::Exit { .. }) => saw_exit = true,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let summary = tracer.finish();
        assert!(saw_exit, "round {round}: no Exit");
        assert_eq!(summary.loss.total(), 0, "round {round}: {:?}", summary.loss);
        drop(release);
        drop(out);
    }
    std::thread::sleep(Duration::from_millis(200));
    let threads = count("/proc/self/task");
    let fds = count("/proc/self/fd");
    let zombies = zombies();
    println!("r30: after 20 more cycles threads={threads} fds={fds} zombies={zombies:?}");
    assert!(
        threads <= baseline.0,
        "the tracer thread of each cycle must be joined: {threads} threads, baseline {}",
        baseline.0
    );
    assert!(
        fds <= baseline.1,
        "{fds} descriptors, baseline {}",
        baseline.1
    );
    assert!(zombies.is_empty(), "zombies left behind: {zombies:?}");
}

fn zombies() -> Vec<libc::pid_t> {
    let mut out = Vec::new();
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return out;
    };
    for task in tasks.flatten() {
        let Ok(raw) = std::fs::read_to_string(task.path().join("children")) else {
            continue;
        };
        for field in raw.split_whitespace() {
            let Ok(pid) = field.parse::<libc::pid_t>() else {
                continue;
            };
            let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
                continue;
            };
            if status
                .lines()
                .any(|l| l.starts_with("State:") && l.contains('Z'))
            {
                out.push(pid);
            }
        }
    }
    out
}

/// R31: an entry destroyed by another thread's `execve` is reported as loss
/// that names the operation it would have reported, never as bookkeeping. A
/// consumer gates §11.4 strict mode and class degradation on the gap's op
/// set, so an entry the tracer holds in hand must name the classes it would
/// have changed.
///
/// The same run pins the §11.4 gap time base: the tracer was given the
/// supervisor's start reading as its epoch, so every gap endpoint must be an
/// age since that start — bounded by how long ago the test itself began —
/// and not an instant on the boot clock.
#[test]
fn r31_an_entry_destroyed_by_an_exec_names_its_operation() {
    let _serial = serial();
    let Some(work) = setup("r31") else { return };
    let fifo = work.path("f");
    mkfifo(&fifo);
    let helper = work.helper_s();
    // The supervisor-start reading. Gap endpoints must be elapsed since it.
    let epoch = clock::boottime_ns();
    let mut run = launch(&work, &[&helper, "exec-over-inflight", &fifo, "/bin/true"]);
    let tracer = attach(
        run.pid,
        TracerConfig {
            epoch_boottime_ns: epoch,
            ..TracerConfig::default()
        },
    );
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    Report::find(&reports, "leader");
    let abandoned: Vec<(OpSet, Option<u64>)> = observed
        .gaps()
        .into_iter()
        .filter(|(reason, _, _)| *reason == GapReason::EntryAbandoned)
        .map(|(_, ops, count)| (ops, count))
        .collect();
    assert!(
        !abandoned.is_empty(),
        "the entry that was mid-syscall when the exec destroyed its thread is \
         loss and must be reported:\n  {}",
        observed.describe()
    );
    for (ops, _) in &abandoned {
        assert!(
            !ops.is_empty(),
            "jail-v1 §11.4: a gap over an entry that is in hand must name the \
             classes it affected, not report bookkeeping: {abandoned:?}"
        );
        assert!(
            ops.contains(ClosedOp::Open),
            "the destroyed entry was an openat on a FIFO, so the gap must name \
             the fs class: {abandoned:?}"
        );
    }
    assert!(
        observed.summary.loss.abandoned_entries >= 1,
        "{:?}",
        observed.summary.loss
    );
    // The tree still ends properly: the exec survives as /bin/true and the
    // supervisor receives its exit.
    assert_eq!(
        observed.exits(),
        vec![(run.pid, 0)],
        "{:?}",
        observed.exits()
    );
    // Every gap endpoint is an age since the epoch: at most the time this
    // test has itself been running, and never a boot-clock instant.
    let elapsed = clock::boottime_ns().saturating_sub(epoch);
    for event in &observed.events {
        if let TracerEvent::Gap { from_ns, to_ns, .. } = event {
            assert!(from_ns <= to_ns, "a gap bounds itself: {from_ns} > {to_ns}");
            assert!(
                *to_ns <= elapsed,
                "gap endpoints are elapsed since the supervisor start, but {to_ns} \
                 exceeds the {elapsed} ns this test has been running"
            );
        }
    }
}

// ======================================= execveat and vfork, through the tracer

/// `execveat`, both results of the row. A failed `execveat` is a result with its
/// errno and its pathname; a successful one through `AT_EMPTY_PATH` is the
/// confirmed transition, carrying the descriptor it resolved against and the
/// empty pathname it was given — never a path the observer did not see.
#[test]
fn j4_n8_execveat_failure_and_success_are_distinct_events() {
    let _serial = serial();
    let Some(work) = setup("n8-execveat") else {
        return;
    };
    let helper = work.helper_s();
    let missing = work.path("absent-program");
    let mut run = launch(&work, &[&helper, "execveat", "/bin/true", &missing]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));
    let failed = Report::find(&reports, "execveat_fail");
    assert_eq!(failed.errno, libc::ENOENT, "{reports:?}");
    assert!(
        reports.iter().all(|r| r.label != "execveat_ok"),
        "the second execveat must replace the image: {reports:?}"
    );
    let results: Vec<(String, i64, &'static str)> = observed
        .of_op(ClosedOp::Exec)
        .into_iter()
        .filter_map(|e| match e {
            TracerEvent::Syscall { syscall, ret, .. } => Some((primary(e), *ret, *syscall)),
            _ => None,
        })
        .collect();
    assert_eq!(
        results,
        vec![(missing.clone(), failed.ret(), "execveat")],
        "one failed-exec result, and nothing for the one that succeeded:\n  {}",
        observed.describe()
    );
    type Transition = (libc::pid_t, Option<(Vec<u8>, bool)>, Option<i32>);
    let transitions: Vec<Transition> = observed
        .events
        .iter()
        .filter_map(|e| match e {
            TracerEvent::Exec {
                pid, path, dirfd, ..
            } => Some((
                *pid,
                path.as_ref().map(|p| (p.bytes.clone(), p.complete)),
                *dirfd,
            )),
            _ => None,
        })
        .collect();
    assert_eq!(transitions.len(), 2, "{}", observed.describe());
    let (pid, path, dirfd) = &transitions[1];
    assert_eq!(*pid, run.pid);
    assert_eq!(
        path.as_ref(),
        Some(&(Vec::new(), true)),
        "the snapshot is the empty pathname AT_EMPTY_PATH passed, complete"
    );
    assert!(
        dirfd.is_some_and(|fd| fd >= 0),
        "the transition names the descriptor it resolved against: {dirfd:?}"
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)], "/bin/true exited 0");
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// `vfork` and `posix_spawn`. Both children are born through the vfork path
/// (glibc's `posix_spawn`
/// uses `clone(CLONE_VM|CLONE_VFORK)`, after `clone3` where the kernel and
/// the filters allow it), exec, and exit. Each is attributed to its own
/// pid, as the fixture reported it, with its own confirmed exec and exit;
/// the parent keeps its own.
#[test]
fn j4_n8_vfork_and_posix_spawn_children_keep_their_attribution() {
    let _serial = serial();
    let Some(work) = setup("n8-vfork") else {
        return;
    };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "vfork", "/bin/true"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));
    let vforked = Report::find(&reports, "vfork_child").raw as libc::pid_t;
    let spawned = Report::find(&reports, "spawn_child").raw as libc::pid_t;
    assert!(vforked > 0 && spawned > 0, "{reports:?}");
    assert_ne!(vforked, spawned);
    let forks = observed.forks();
    for child in [vforked, spawned] {
        assert!(
            forks.contains(&(run.pid, child)),
            "child {child} must be tracked from its birth: {forks:?}"
        );
    }
    let mut execs = observed.execs();
    execs.sort_unstable();
    let mut want = vec![run.pid, vforked, spawned];
    want.sort_unstable();
    assert_eq!(execs, want, "{}", observed.describe());
    let mut exits = observed.exits();
    exits.sort_unstable();
    let mut want: Vec<(libc::pid_t, i32)> = vec![(run.pid, 0), (vforked, 0), (spawned, 0)];
    want.sort_unstable();
    assert_eq!(exits, want, "{}", observed.describe());
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}
