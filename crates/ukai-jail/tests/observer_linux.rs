#![cfg(target_os = "linux")]
//! The live harness for the Linux ptrace observer.
//!
//! Every test here runs a real process tree on a real kernel, seizes it with
//! [`Tracer::attach`] and compares what the observer reported with what the
//! traced program said about itself. The fixture prints the raw return and
//! errno of every call it makes, so the comparison is result by result and
//! errno by errno, not "an event turned up".
//!
//! The fixture is a small C program built at test time
//! (`fixtures/observer.c`). It doubles as the inside launcher of jail-v1
//! §3.6: it installs the narrowing filter this crate produces — read from a
//! file, never a second copy of the program — blocks reading one byte from
//! stdin, and then execs the target. That is exactly the sequence the
//! product's launcher performs, so the tests exercise the attach window as it
//! will really exist (`common/observer.rs`).
//!
//! Tests skip with a reason when a tool they need is missing. Under
//! `UKAI_CONFORMANCE=1` a skip is a failure.

use std::collections::BTreeMap;
use std::io::BufRead as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ukai_jail::platform::linux::tracer::{
    ClosedOp, GapReason, OpSet, Tracer, TracerConfig, TracerError, TracerEvent, narrowing_filter,
    narrowing_filter_bytes, narrowing_filter_digest, nspid,
};

mod common;

use common::observer::{
    Fixture, Observed, Report, Work, attach, collect, find_launcher, launch, native_expectation,
    paths, serial, spawn_launcher,
};

/// The launcher and every fixture, in one binary.
static FIXTURE: Fixture = Fixture {
    name: "observer",
    source: include_str!("fixtures/observer.c"),
    pthread: true,
    filter: narrowing_filter_bytes,
};

/// Prepare a test. `None` means the test skipped and must return.
fn setup(name: &str, tools: &[&str]) -> Option<Work> {
    FIXTURE.setup(name, tools)
}

fn describe(event: &TracerEvent) -> String {
    match event {
        TracerEvent::Syscall {
            tid,
            op,
            syscall,
            ret,
            ..
        } => {
            let (a, b) = paths(event);
            format!("{tid} {syscall} ({}) {a} {b} = {ret}", op.as_str())
        }
        other => format!("{other:?}"),
    }
}

// ------------------------------------------------------------------ tests

/// O01: every closed-set result the observer reports is the result the
/// traced program says it got, with the same errno, the same paths and the
/// same syscall; and a read-only open produces no event at all.
#[test]
fn o01_every_closed_set_result_matches_the_fixture() {
    let _serial = serial();
    let Some(work) = setup("o01", &["/usr/bin/gcc"]) else {
        return;
    };
    use std::os::unix::fs::PermissionsExt;
    let locked = work.path("locked");
    std::fs::write(&locked, b"x").expect("create the locked file");
    std::fs::set_permissions(&locked, PermissionsExt::from_mode(0o000)).expect("chmod 000");

    let helper = work.helper.to_string_lossy().into_owned();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "closed-set", &base, &locked]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    // label -> the syscall and operation it must produce, or None when the
    // closed set does not cover it.
    let expected: &[(&str, Option<(&str, ClosedOp)>)] = &[
        ("open_create", Some(("openat", ClosedOp::Open))),
        ("open_rdonly", None),
        ("open_write", Some(("openat", ClosedOp::Open))),
        ("open_enoent", Some(("openat", ClosedOp::Open))),
        ("mkdir", Some(("mkdir", ClosedOp::Mkdir))),
        ("mkdir_eexist", Some(("mkdir", ClosedOp::Mkdir))),
        ("rename", Some(("rename", ClosedOp::Rename))),
        ("link", Some(("link", ClosedOp::Link))),
        ("symlink", Some(("symlink", ClosedOp::Symlink))),
        ("unlink", Some(("unlink", ClosedOp::Unlink))),
        ("unlink_enoent", Some(("unlink", ClosedOp::Unlink))),
        ("rmdir", Some(("rmdir", ClosedOp::Rmdir))),
        ("connect", Some(("connect", ClosedOp::Connect))),
        ("open_eacces", Some(("openat", ClosedOp::Open))),
        ("creat", Some(("creat", ClosedOp::Open))),
        ("renameat2", Some(("renameat2", ClosedOp::Rename))),
        ("unlinkat", Some(("unlinkat", ClosedOp::Unlink))),
        ("mkdirat", Some(("mkdirat", ClosedOp::Mkdir))),
        ("unlinkat_removedir", Some(("unlinkat", ClosedOp::Unlink))),
        ("open", Some(("open", ClosedOp::Open))),
        ("linkat", Some(("linkat", ClosedOp::Link))),
        ("symlinkat", Some(("symlinkat", ClosedOp::Symlink))),
        ("openat2", Some(("openat2", ClosedOp::Open))),
        ("truncate", Some(("truncate", ClosedOp::Truncate))),
        ("mknod", Some(("mknod", ClosedOp::Mknod))),
        ("mknodat", Some(("mknodat", ClosedOp::Mknod))),
        // `ftruncate` mutates through a descriptor, like `write`, and is
        // named in §11.2 as excluded.
        ("ftruncate", None),
        // With the four rows below, every row of the native table is
        // compared one to one.
        ("execve_enoent", Some(("execve", ClosedOp::Exec))),
        ("execveat_enoent", Some(("execveat", ClosedOp::Exec))),
        ("renameat", Some(("renameat", ClosedOp::Rename))),
        ("connect_ok", Some(("connect", ClosedOp::Connect))),
    ];
    let expected: Vec<_> = expected
        .iter()
        .map(|(label, expectation)| {
            (
                *label,
                expectation.map(|(syscall, op)| native_expectation(syscall, op)),
            )
        })
        .collect();
    // Every native row is compared, including the legacy x86_64 spellings.
    let rows: std::collections::BTreeSet<&str> = expected
        .iter()
        .filter_map(|(_, e)| e.map(|(syscall, _)| syscall))
        .collect();
    assert_eq!(
        rows.len(),
        if cfg!(target_arch = "aarch64") {
            13
        } else {
            22
        },
        "{rows:?}"
    );
    let labels: Vec<&str> = reports.iter().map(|r| r.label.as_str()).collect();
    assert_eq!(
        labels,
        expected.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
        "the fixture must report every operation, in order"
    );
    // A few results the test asserts itself, so the comparison below cannot
    // pass by both sides being wrong in the same way.
    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    assert_eq!(
        by_label["open_enoent"].errno,
        libc::ENOENT,
        "a missing directory"
    );
    assert_eq!(
        by_label["mkdir_eexist"].errno,
        libc::EEXIST,
        "the second mkdir"
    );
    assert_eq!(
        by_label["unlink_enoent"].errno,
        libc::ENOENT,
        "the second unlink"
    );
    assert_eq!(
        by_label["connect"].errno,
        libc::ENOENT,
        "a socket that is not there"
    );
    assert_eq!(
        by_label["open_eacces"].errno,
        libc::EACCES,
        "a mode 0000 file"
    );
    assert_eq!(
        by_label["open_rdonly"].errno, 0,
        "the read-only open must succeed"
    );
    assert_eq!(by_label["execve_enoent"].errno, libc::ENOENT);
    assert_eq!(by_label["execveat_enoent"].errno, libc::ENOENT);
    assert_eq!(by_label["renameat"].raw, 0, "the renameat succeeds");
    assert_eq!(by_label["connect_ok"].raw, 0, "the connect succeeds");

    // Only the events about this test's files. Nothing else reaches the
    // fixture's own paths, so this drops the loader's read-only opens
    // without dropping anything the fixture did.
    let ours: Vec<&TracerEvent> = observed
        .syscalls()
        .into_iter()
        .filter(|event| {
            let (a, b) = paths(event);
            a.starts_with(&base)
                || b.starts_with(&base)
                || matches!(
                    event,
                    TracerEvent::Syscall {
                        op: ClosedOp::Connect,
                        ..
                    }
                )
        })
        .collect();
    let wanted: Vec<&(&str, Option<(&str, ClosedOp)>)> =
        expected.iter().filter(|(_, e)| e.is_some()).collect();
    assert_eq!(
        ours.len(),
        wanted.len(),
        "observed:\n  {}\nexpected {} results",
        ours.iter()
            .map(|e| describe(e))
            .collect::<Vec<_>>()
            .join("\n  "),
        wanted.len()
    );
    for (event, (label, expectation)) in ours.iter().zip(wanted.iter()) {
        let (want_syscall, want_op) = expectation.expect("filtered to Some");
        let report = by_label[label];
        let TracerEvent::Syscall {
            op,
            syscall,
            ret,
            args,
            ..
        } = event
        else {
            unreachable!("filtered to syscalls")
        };
        assert_eq!(*syscall, want_syscall, "{label}: syscall");
        assert_eq!(*op, want_op, "{label}: operation");
        assert_eq!(*ret, report.ret(), "{label}: return value");
        if want_op == ClosedOp::Connect {
            let sockaddr = args.sockaddr.as_ref().expect("connect carries a sockaddr");
            assert_eq!(
                sockaddr.family,
                Some(libc::AF_UNIX as u16),
                "{label}: family"
            );
            assert!(
                sockaddr.complete,
                "{label}: the whole address the caller declared was readable"
            );
        } else {
            let (a, b) = paths(event);
            assert_eq!(a, report.path, "{label}: path");
            assert_eq!(b, report.path2, "{label}: second path");
            let snapshot = args.path.as_ref().expect("a path snapshot");
            assert!(
                snapshot.complete,
                "{label}: the path snapshot must be complete"
            );
        }
    }

    // The read-only open is outside the set: not an event, not a loss.
    assert!(
        observed.summary.filtered_readonly_opens >= 1,
        "the read-only open must be counted as filtered, not lost"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
    assert_eq!(observed.gaps(), vec![], "no gaps in a clean run");
    assert_eq!(
        observed.execs(),
        vec![run.pid],
        "one confirmed exec: the launcher's"
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)], "one exit, status 0");
    assert!(observed.finished(), "the tracer must report Finished");
}

/// O01/O06 through bubblewrap: the same evidence for a process in a pid and
/// user namespace, found by walking `/proc` rather than by having forked it,
/// with the host pid in the events and the namespace pid in the process.
#[test]
fn o01_through_bubblewrap_carries_host_pids_for_namespace_processes() {
    let _serial = serial();
    if !common::live() {
        return;
    }
    let Some(work) = setup("bwrap", &["/usr/bin/gcc"]) else {
        return;
    };
    let build_dir = work
        .helper
        .parent()
        .expect("the helper lives in a directory")
        .to_path_buf();
    let mut command = Command::new(common::bwrap_path());
    command
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
        ])
        .arg(&build_dir)
        .args([
            "/ukai",
            "--",
            "/ukai/helper",
            "launch",
            "/ukai/filter.bin",
            "/ukai/helper",
            "shell-ops",
            "/tmp",
        ]);
    let mut run = spawn_launcher(command);
    let bwrap = run.pid;
    let Some(inner) = find_launcher(bwrap, b"/ukai/helper", Duration::from_secs(15)) else {
        panic!("the inside launcher never appeared under bwrap {bwrap}");
    };
    let ns = nspid(inner).expect("NSpid of the inside launcher");
    let tracer = attach(inner, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    assert!(
        ns.len() >= 2,
        "the launcher must be inside a pid namespace: {ns:?}"
    );
    assert_eq!(
        ns[0], inner,
        "the first NSpid entry is the host pid we seized"
    );
    let inside = *ns.last().expect("a namespace pid");
    assert_ne!(
        inside, inner,
        "host pid {inner} must differ from namespace pid {inside}"
    );
    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    assert_eq!(
        by_label["nspid"].raw,
        i64::from(inside),
        "the process sees its namespace pid; the observer reports the host pid"
    );

    let expected: &[(&str, &str, ClosedOp)] = &[
        ("open_create", "openat", ClosedOp::Open),
        ("rename", "rename", ClosedOp::Rename),
        ("unlink", "unlink", ClosedOp::Unlink),
        ("mkdir", "mkdir", ClosedOp::Mkdir),
        ("rmdir", "rmdir", ClosedOp::Rmdir),
    ];
    let ours: Vec<&TracerEvent> = observed
        .syscalls()
        .into_iter()
        .filter(|event| {
            let (a, b) = paths(event);
            a.starts_with("/tmp/") || b.starts_with("/tmp/")
        })
        .collect();
    assert_eq!(
        ours.len(),
        expected.len(),
        "observed:\n  {}",
        ours.iter()
            .map(|e| describe(e))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    for (event, (label, want_syscall, want_op)) in ours.iter().zip(expected.iter()) {
        let report = by_label[label];
        let TracerEvent::Syscall {
            pid,
            op,
            syscall,
            ret,
            ..
        } = event
        else {
            unreachable!()
        };
        let (want_syscall, want_op) = native_expectation(want_syscall, *want_op);
        assert_eq!(*syscall, want_syscall, "{label}");
        assert_eq!(*op, want_op, "{label}");
        assert_eq!(*ret, report.ret(), "{label}");
        assert_eq!(*pid, inner, "{label}: events carry the host pid");
        let (a, b) = paths(event);
        assert_eq!(a, report.path, "{label}: path");
        assert_eq!(b, report.path2, "{label}: second path");
    }
    assert_eq!(
        observed.exits(),
        vec![(inner, 0)],
        "the inside process exited 0"
    );
    assert!(
        observed
            .untraced_exits()
            .iter()
            .any(|(pid, _)| *pid == bwrap),
        "bubblewrap is a child of this process and never a tracee: {:?}",
        observed.untraced_exits()
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// O02: a failed exec is a result with an errno, a successful one is the
/// confirmed transition, and the two are never confused.
#[test]
fn o02_exec_success_and_failure_are_distinct_events() {
    let _serial = serial();
    let Some(work) = setup("exec", &["/usr/bin/gcc", "/bin/true"]) else {
        return;
    };
    use std::os::unix::fs::PermissionsExt;
    let missing = work.path("absent-program");
    let noexec = work.path("not-executable");
    std::fs::write(&noexec, b"#!/nope\n").expect("create the non-executable file");
    std::fs::set_permissions(&noexec, PermissionsExt::from_mode(0o644)).expect("chmod 644");

    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "exec-cases", &missing, &noexec]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    assert_eq!(by_label["execve_enoent"].errno, libc::ENOENT);
    assert_eq!(by_label["execve_eacces"].errno, libc::EACCES);
    assert!(
        !by_label.contains_key("execve_true"),
        "the last exec must succeed, so the fixture never reports it"
    );

    let failures: Vec<(String, i64)> = observed
        .syscalls()
        .into_iter()
        .filter_map(|event| match event {
            TracerEvent::Syscall {
                op: ClosedOp::Exec,
                ret,
                ..
            } => Some((paths(event).0, *ret)),
            _ => None,
        })
        .collect();
    assert_eq!(
        failures,
        vec![
            (missing.clone(), -i64::from(libc::ENOENT)),
            (noexec.clone(), -i64::from(libc::EACCES)),
        ],
        "a failed exec is a result with the errno the caller saw"
    );
    assert_eq!(
        observed.execs(),
        vec![run.pid, run.pid],
        "two confirmed transitions: into the fixture and into /bin/true"
    );
    assert_eq!(observed.summary.exec_transitions, 2);
    // A confirmed transition names the image by the pathname snapshot of the
    // entry it was paired with: an argument snapshot rather than a resolved
    // path (§11.3).
    let images: Vec<String> = observed
        .events
        .iter()
        .filter_map(|event| match event {
            TracerEvent::Exec { path, .. } => Some(
                path.as_ref()
                    .map(|p| String::from_utf8_lossy(&p.bytes).into_owned())
                    .unwrap_or_default(),
            ),
            _ => None,
        })
        .collect();
    assert_eq!(
        images,
        vec![helper.clone(), "/bin/true".to_string()],
        "each transition carries the pathname its entry asked for"
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)], "/bin/true exited 0");
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// O02: a fork child that never execs is tracked and reaped, and emits no
/// `proc.exit` — the spec ties that event to a witnessed exec.
#[test]
fn o02_a_fork_child_that_never_execs_emits_no_exit() {
    let _serial = serial();
    let Some(work) = setup("fork", &["/usr/bin/gcc"]) else {
        return;
    };
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "fork-once"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    let child = by_label["child"].raw as libc::pid_t;
    assert_eq!(
        by_label["parent"].raw as libc::pid_t, child,
        "the fixture waited for it"
    );

    assert!(
        observed.forks().contains(&(run.pid, child)),
        "the fork must be tracked: {:?}",
        observed.forks()
    );
    assert_eq!(
        observed.exits(),
        vec![(run.pid, 0)],
        "only the process that was seen to exec produces an Exit"
    );
    assert_eq!(observed.summary.reaped_tasks, 2, "both tasks were reaped");
    assert_eq!(observed.summary.exits, 1);
    assert_eq!(observed.summary.tracees, 2);
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// O02: a leader that calls `pthread_exit` while four workers are alive is
/// not a process death. Exactly one `Exit` arrives, at the end, with the
/// group's status and not a worker's.
#[test]
fn o02_a_leader_leaving_live_workers_emits_exactly_one_exit() {
    let _serial = serial();
    let Some(work) = setup("threads", &["/usr/bin/gcc"]) else {
        return;
    };
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "threads", "leader-exit"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    assert_eq!(
        reports.iter().filter(|r| r.label == "worker").count(),
        4,
        "all four workers must outlive the leader and finish"
    );
    assert_eq!(reports.iter().filter(|r| r.label == "leader").count(), 1);
    assert_eq!(
        observed.exits(),
        vec![(run.pid, 0)],
        "one Exit, for the thread group, after the last thread"
    );
    assert_eq!(observed.summary.exits, 1);
    assert_eq!(
        observed.summary.tracees, 5,
        "the leader and its four workers were all tracked"
    );
    assert_eq!(
        observed.summary.reaped_tasks, 5,
        "every thread death was reaped"
    );
    assert_eq!(
        observed.summary.loss.final_status_unknown, 0,
        "the leader was the last thread reaped, so the status is the group's"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// O02: a worker thread that execs becomes the leader. The process keeps the
/// identity it was born with, and one confirmed transition is reported.
#[test]
fn o02_a_non_leader_exec_keeps_the_birth_identity() {
    let _serial = serial();
    let Some(work) = setup("nonleader", &["/usr/bin/gcc", "/bin/true"]) else {
        return;
    };
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "threads", "worker-exec", "/bin/true"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let _ = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    assert_eq!(
        observed.execs(),
        vec![run.pid, run.pid],
        "the exec from a worker is reported under the identity the process was born with"
    );
    assert_eq!(observed.summary.exec_transitions, 2);
    assert_eq!(
        observed.exits(),
        vec![(run.pid, 0)],
        "one Exit, under the same identity, when /bin/true finishes"
    );
    assert_eq!(observed.summary.exits, 1);
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
    // O02: the birth the events name is the one the process was attached
    // with — the kernel gives the exec'ing worker the leader's start time —
    // on both transitions and on the exit.
    let attached = observed
        .events
        .iter()
        .find_map(|e| match e {
            TracerEvent::Attached { start_ticks, .. } => *start_ticks,
            _ => None,
        })
        .expect("the attach names the launcher's birth");
    let births: Vec<Option<u64>> = observed
        .events
        .iter()
        .filter_map(|e| match e {
            TracerEvent::Exec { start_ticks, .. } | TracerEvent::Exit { start_ticks, .. } => {
                Some(*start_ticks)
            }
            _ => None,
        })
        .collect();
    assert_eq!(births, vec![Some(attached); 3], "{:?}", observed.events);
}

/// The fail-closed property the supervisor relies on: with the narrowing
/// filter installed and no tracer attached, a closed-set call does not run.
/// It fails with ENOSYS. If the observer dies, the target stops working
/// rather than proceeding unobserved.
#[test]
fn the_narrowing_filter_without_a_tracer_fails_closed_with_enosys() {
    let _serial = serial();
    let Some(work) = setup("enosys", &["/usr/bin/gcc"]) else {
        return;
    };
    let target = work.path("never-created");
    let mut run = launch(&work, &["--probe-openat", &target]);
    // No tracer at all.
    run.release();
    let reports = run.lines();
    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();

    assert_eq!(
        by_label["openat_create"].errno,
        libc::ENOSYS,
        "a covered open must not run without a tracer"
    );
    assert_eq!(by_label["openat_create"].raw, -1);
    assert_eq!(
        by_label["openat_rdonly"].errno,
        libc::ENOSYS,
        "the filter traces by syscall number, so a read-only open fails too"
    );
    assert_eq!(
        by_label["write"].errno, 0,
        "a syscall outside the closed set is allowed straight through"
    );
    assert!(
        !Path::new(&target).exists(),
        "the syscall must not have run: ENOSYS is refusal, not a silent success"
    );
}

/// O03: a consumer that does not read cannot stop the tree. Loss is bounded,
/// counted exactly, coalesced into one gap, and no result is duplicated or
/// invented.
#[test]
fn o03_queue_loss_is_bounded_counted_and_coalesced() {
    let _serial = serial();
    let Some(work) = setup("loss", &["/usr/bin/gcc"]) else {
        return;
    };
    const STORM: u64 = 20_000;
    const QUEUE: usize = 64;
    let target = work.path("storm-target");
    let helper = work.helper.to_string_lossy().into_owned();
    let storm = STORM.to_string();
    let mut run = launch(&work, &[&helper, "storm", &storm, &target]);
    let tracer = attach(
        run.pid,
        TracerConfig {
            queue_max: QUEUE,
            ..TracerConfig::default()
        },
    );
    let started = Instant::now();
    run.release();

    // The fixture prints this after all 20,000 calls. Nothing has been read
    // from the queue yet, so backpressure has already engaged.
    let mut line = String::new();
    run.output.read_line(&mut line).expect("the storm report");
    let report = Report::parse(line.trim_end()).expect("a storm report");
    assert_eq!(report.label, "storm");
    assert_eq!(report.raw, STORM as i64);
    assert!(
        started.elapsed() < Duration::from_secs(120),
        "a stalled consumer must never hold the tree indefinitely"
    );

    // Start reading, which frees the queue.
    let mut events = Vec::new();
    while let Ok(event) = tracer.events().recv_timeout(Duration::from_millis(500)) {
        events.push(event);
    }
    // One more call, so the gap the tracer has been carrying is delivered
    // ahead of the result that follows it.
    run.release();
    let rest = collect(tracer, Duration::from_secs(30));
    events.extend(rest.events);
    let observed = Observed {
        events,
        summary: rest.summary,
    };

    assert_eq!(
        observed.summary.ops.get(ClosedOp::Open),
        STORM,
        "every call was observed exactly once, whether or not it could be delivered"
    );
    assert!(
        observed.summary.loss.queue_dropped > 0,
        "the queue was 64 events deep and 20,000 arrived"
    );
    let queue_gaps: Vec<(GapReason, OpSet, Option<u64>)> = observed
        .gaps()
        .into_iter()
        .filter(|(reason, _, _)| *reason == GapReason::QueueFull)
        .collect();
    assert!(!queue_gaps.is_empty(), "the loss must be reported as a gap");
    for (_, _, count) in &queue_gaps {
        assert!(
            count.is_some(),
            "the count of dropped events is known exactly"
        );
    }
    let counted: u64 = queue_gaps.iter().filter_map(|(_, _, c)| *c).sum();
    assert_eq!(
        counted, observed.summary.loss.queue_dropped,
        "the gap accounts for every dropped event"
    );
    let delivered: Vec<&TracerEvent> = observed
        .syscalls()
        .into_iter()
        .filter(|e| {
            matches!(
                e,
                TracerEvent::Syscall {
                    op: ClosedOp::Open,
                    ..
                }
            )
        })
        .collect();
    assert!(
        (delivered.len() as u64) < STORM,
        "some results were dropped, so not all of them can have been delivered"
    );
    for event in &delivered {
        assert_eq!(
            paths(event).0,
            target,
            "no delivered result names a path nobody asked for"
        );
    }
    assert!(
        observed.syscalls().iter().any(|e| matches!(
            e,
            TracerEvent::Syscall {
                op: ClosedOp::Mkdir,
                ..
            }
        )),
        "the call made after the queue recovered is reported"
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)]);
}

/// O04: `write`, `read` and `mmap` are outside the closed set. They produce
/// no events, and the filter does not even stop for them.
#[test]
fn o04_write_read_and_mmap_produce_no_events_and_no_stops() {
    let _serial = serial();
    let Some(work) = setup("o04", &["/usr/bin/gcc"]) else {
        return;
    };
    const ITERATIONS: i64 = 1000;
    let target = work.path("rwm-target");
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "rwm", &target, &ITERATIONS.to_string()]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    assert_eq!(
        by_label["done"].raw, ITERATIONS,
        "the fixture ran the whole loop"
    );

    let ours: Vec<&TracerEvent> = observed
        .syscalls()
        .into_iter()
        .filter(|event| paths(event).0 == target)
        .collect();
    assert_eq!(
        ours.len(),
        1,
        "only the open is covered: {}",
        ours.iter()
            .map(|e| describe(e))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert_eq!(observed.summary.ops.get(ClosedOp::Open), 1);
    assert_eq!(observed.summary.ops.total(), 1, "nothing else is claimed");
    assert!(
        observed.summary.stops < 100,
        "{} stops for {ITERATIONS} write/read/mmap rounds: they must not stop at all",
        observed.summary.stops
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// A denied operation is the original operation with the errno the kernel
/// gave it. Classifying it is the consumer's job; the observer delivers the
/// result. EROFS comes from a read-only bind inside bubblewrap, EACCES from
/// a mode 0000 file (asserted by `o01_every_closed_set_result_matches_the_fixture`).
#[test]
fn o01_a_denied_write_keeps_its_own_operation_and_errno() {
    let _serial = serial();
    if !common::live() {
        return;
    }
    let Some(work) = setup("denied", &["/usr/bin/gcc"]) else {
        return;
    };
    let build_dir = work.helper.parent().expect("a directory").to_path_buf();
    let mut command = Command::new(common::bwrap_path());
    command
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
        ])
        .arg(&build_dir)
        .args([
            "/ukai",
            "--",
            "/ukai/helper",
            "launch",
            "/ukai/filter.bin",
            "/ukai/helper",
            "denied",
            "/ukai/forbidden",
        ]);
    let mut run = spawn_launcher(command);
    let Some(inner) = find_launcher(run.pid, b"/ukai/helper", Duration::from_secs(15)) else {
        panic!("the inside launcher never appeared");
    };
    let tracer = attach(inner, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    assert_eq!(
        by_label["open_erofs"].errno,
        libc::EROFS,
        "a read-only bind denies a create with EROFS"
    );
    assert_eq!(by_label["mkdir_erofs"].errno, libc::EROFS);

    let ours: Vec<(String, ClosedOp, i64)> = observed
        .syscalls()
        .into_iter()
        .filter(|e| paths(e).0 == "/ukai/forbidden")
        .map(|e| match e {
            TracerEvent::Syscall { op, ret, .. } => (paths(e).0, *op, *ret),
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(
        ours,
        vec![
            (
                "/ukai/forbidden".to_string(),
                ClosedOp::Open,
                -i64::from(libc::EROFS)
            ),
            (
                "/ukai/forbidden".to_string(),
                ClosedOp::Mkdir,
                -i64::from(libc::EROFS)
            ),
        ],
        "the denial is reported as the operation that was attempted"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// The file workload the observer's cost is measured on, under the shipped
/// tracer: every open, rename and unlink is observed exactly once, with no
/// loss. Its cost, traced and untraced, is printed beside the ptrace spike's
/// on the reference host for comparison, and not asserted: wall-clock time
/// depends on the host, and the perf gate (`cargo xtask perf`) is where cost
/// is judged.
#[test]
fn the_file_workload_is_observed_call_for_call() {
    let _serial = serial();
    let Some(work) = setup("perf", &["/usr/bin/gcc"]) else {
        return;
    };
    const ROUNDS: &str = "5000";
    let base = work.base();
    let helper = work.helper.to_string_lossy().into_owned();

    let untraced_start = Instant::now();
    let status = Command::new(&work.helper)
        .args(["fileops", ROUNDS, &base])
        .stdout(Stdio::null())
        .status()
        .expect("run the workload untraced");
    let untraced = untraced_start.elapsed();
    assert!(status.success(), "the untraced run must succeed");

    let mut run = launch(&work, &[&helper, "fileops", ROUNDS, &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    let traced_start = Instant::now();
    run.release();
    let observed = collect(tracer, Duration::from_secs(300));
    let traced = traced_start.elapsed();

    println!(
        "perf fileops rounds={ROUNDS}: untraced={:.3}s traced={:.3}s ratio={:.1}x \
         (the ptrace spike on the reference host: narrow median 0.81s, untraced 0.15s)",
        untraced.as_secs_f64(),
        traced.as_secs_f64(),
        traced.as_secs_f64() / untraced.as_secs_f64().max(0.001),
    );
    println!(
        "perf accounting: stops={} events={} open={} rename={} unlink={} loss={}",
        observed.summary.stops,
        observed.summary.emitted,
        observed.summary.ops.get(ClosedOp::Open),
        observed.summary.ops.get(ClosedOp::Rename),
        observed.summary.ops.get(ClosedOp::Unlink),
        observed.summary.loss.total(),
    );
    assert_eq!(observed.summary.ops.get(ClosedOp::Open), 5000);
    assert_eq!(observed.summary.ops.get(ClosedOp::Rename), 5000);
    assert_eq!(observed.summary.ops.get(ClosedOp::Unlink), 5000);
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)]);
}

/// The preconditions of `attach`, tried from the outside: a pid that is not
/// ours, and one that is already traced.
#[test]
fn attach_refuses_what_it_may_not_trace() {
    let _serial = serial();
    let Some(work) = setup("preconditions", &["/usr/bin/gcc"]) else {
        return;
    };
    match Tracer::attach(1, TracerConfig::default()) {
        Err(TracerError::Seize { pid: 1, errno }) => {
            assert!(
                errno == libc::EPERM || errno == libc::ESRCH,
                "errno {errno}"
            );
        }
        other => panic!("seizing pid 1 must be refused, got {other:?}"),
    }
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "fork-once"]);
    let tracer = attach(run.pid, TracerConfig::default());
    match Tracer::attach(run.pid, TracerConfig::default()) {
        Err(TracerError::Seize { errno, .. }) => {
            assert_eq!(errno, libc::EPERM, "a second seize of the same task");
        }
        other => panic!("a task can only have one tracer, got {other:?}"),
    }
    run.release();
    let observed = collect(tracer, Duration::from_secs(30));
    assert!(observed.finished());
}

/// The filter the launcher installs is the one this crate publishes, and its
/// digest names those bytes.
#[test]
fn the_launcher_installs_the_published_filter() {
    let _serial = serial();
    let Some(work) = setup("filter", &["/usr/bin/gcc"]) else {
        return;
    };
    let on_disk = std::fs::read(&work.filter).expect("read the filter file");
    assert_eq!(
        on_disk,
        narrowing_filter_bytes(),
        "the fixture installs our bytes"
    );
    assert_eq!(on_disk.len(), narrowing_filter().len() * 8);
    let digest = narrowing_filter_digest();
    assert!(
        digest.starts_with("sha256:") && digest.len() == 71,
        "{digest}"
    );
    println!(
        "narrowing filter: {} instructions, {digest}",
        narrowing_filter().len()
    );
}

/// O06: a pathname is bytes. What the caller passed is what the snapshot
/// holds, whether or not it is text; and a snapshot that did not reach the
/// end of the name says so instead of presenting a prefix as the name.
#[test]
fn o06_a_path_is_bytes_and_a_short_snapshot_declares_itself_incomplete() {
    let _serial = serial();
    let Some(work) = setup("o06", &["/usr/bin/gcc"]) else {
        return;
    };
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let mut raw = work.base().into_bytes();
    raw.extend_from_slice(b"/na");
    raw.push(0xff);
    raw.extend_from_slice(b"me-longer-than-the-small-snapshot-bound");
    assert!(
        String::from_utf8(raw.clone()).is_err(),
        "the name really is not UTF-8"
    );
    let arg = OsString::from_vec(raw.clone());

    let open_path = |config: TracerConfig| {
        let mut command = work.launcher();
        command.arg(&work.helper).arg("open-path").arg(&arg);
        let mut run = spawn_launcher(command);
        let pid = run.pid;
        let tracer = attach(pid, config);
        run.release();
        let _ = run.raw_output();
        let observed = collect(tracer, Duration::from_secs(30));
        let snapshot = observed
            .syscalls()
            .into_iter()
            .find_map(|event| match event {
                TracerEvent::Syscall {
                    op: ClosedOp::Open,
                    args,
                    ..
                } => args.path.clone(),
                _ => None,
            })
            .expect("the covered open must be observed");
        (snapshot, observed)
    };

    let (whole, observed) = open_path(TracerConfig::default());
    assert_eq!(
        whole.bytes, raw,
        "the snapshot is the caller's bytes, not a lossy rendering"
    );
    assert!(
        whole.complete,
        "4096 bytes is more than enough for this name"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );

    let (short, observed) = open_path(TracerConfig {
        path_snapshot_max: 16,
        ..TracerConfig::default()
    });
    assert_eq!(
        short.bytes,
        raw[..16].to_vec(),
        "what was read is a prefix of the name"
    );
    assert!(
        !short.complete,
        "and it must not be presented as the whole name"
    );
    // The launcher's own `execve` path is longer than sixteen bytes too, so
    // it is counted here as well; what matters is that each one says so.
    assert!(
        observed.summary.loss.path_truncated >= 1,
        "a snapshot that stopped at the bound must be counted"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "a truncated path is a weaker claim, not a lost result: {:?}",
        observed.summary.loss
    );
    assert_eq!(
        observed.summary.ops.get(ClosedOp::Open),
        1,
        "the result itself is still reported"
    );
}

/// O03/L4: an `open_how` the kernel would reject is metadata nobody can
/// decode, so membership of the covered mutation set was never established.
/// No covered `Open` is delivered, nothing is guessed, and because the kernel
/// rejected the same structure there is no covered operation to have missed:
/// the call is counted as an invalid argument, not as lost coverage.
#[test]
fn o03_an_undecodable_open_how_is_never_a_covered_open() {
    let _serial = serial();
    let Some(work) = setup("openhow", &["/usr/bin/gcc"]) else {
        return;
    };
    let target = work.path("openat2-short");
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "openat2-short", &target]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    let report = reports
        .iter()
        .find(|r| r.label == "openat2_short")
        .expect("the fixture reports its openat2");
    assert_eq!(
        report.errno,
        libc::EINVAL,
        "the kernel refuses a short open_how too"
    );

    assert!(
        observed.syscalls().iter().all(|event| !matches!(
            event,
            TracerEvent::Syscall {
                syscall: "openat2",
                ..
            }
        )),
        "an open whose flags could not be decoded must not be delivered as a \
         covered Open: {}",
        observed
            .syscalls()
            .iter()
            .map(|e| describe(e))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(!Path::new(&target).exists(), "and the call really did fail");
    assert_eq!(
        observed.summary.argument_invalid, 1,
        "the kernel rejected the same structure, so this is the tracee's \
         argument and not the observer's coverage"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "a tracee must not be able to manufacture loss: {:?}",
        observed.summary.loss
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)]);
}

/// `Exit` carries the raw wait status, so a consumer can tell a process that
/// exited from one that was killed. A signal death is not an exit code.
#[test]
fn o02_an_exit_carries_the_raw_wait_status_of_a_signal_death() {
    let _serial = serial();
    let Some(work) = setup("raise", &["/usr/bin/gcc"]) else {
        return;
    };
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "raise"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    assert_eq!(
        reports.len(),
        1,
        "the fixture announces itself and then dies"
    );
    let exits = observed.exits();
    assert_eq!(exits.len(), 1, "one thread group died: {exits:?}");
    let (pid, status) = exits[0];
    assert_eq!(pid, run.pid);
    assert!(
        libc::WIFSIGNALED(status),
        "status {status:#x} must say the process was killed, not that it returned"
    );
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
    assert!(
        !libc::WIFEXITED(status),
        "a signal death has no exit code to report"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// O03: the in-flight bound of §11.4 is real. When it is reached, entries
/// are refused and counted, and the results that would have followed become
/// gaps rather than events the observer cannot stand behind.
#[test]
fn o03_the_in_flight_bound_refuses_entries_and_reports_no_results() {
    let _serial = serial();
    let Some(work) = setup("inflight", &["/usr/bin/gcc"]) else {
        return;
    };
    use std::os::unix::fs::PermissionsExt;
    let locked = work.path("locked");
    std::fs::write(&locked, b"x").expect("create the locked file");
    std::fs::set_permissions(&locked, PermissionsExt::from_mode(0o000)).expect("chmod 000");
    let helper = work.helper.to_string_lossy().into_owned();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "closed-set", &base, &locked]);
    let tracer = attach(
        run.pid,
        TracerConfig {
            inflight_max: 0,
            ..TracerConfig::default()
        },
    );
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    assert_eq!(
        reports.len(),
        31,
        "the fixture still runs: the bound is ours, not the tracee's"
    );
    assert!(
        observed.syscalls().is_empty(),
        "no entry could be recorded, so no result is claimed"
    );
    assert_eq!(observed.summary.ops.total(), 0);
    assert!(
        observed.summary.loss.inflight_rejected >= 30,
        "every closed-set entry was refused: {}",
        observed.summary.loss.inflight_rejected
    );
    assert_eq!(
        observed.summary.loss.unmatched_exits, 0,
        "a refused entry is not stepped to an exit"
    );
    assert!(
        observed
            .gaps()
            .iter()
            .any(|(reason, _, _)| *reason == GapReason::InflightExhausted),
        "the refusals are reported as gaps: {:?}",
        observed.gaps()
    );
    // Exec and exit tracking do not depend on the in-flight table.
    assert_eq!(observed.execs(), vec![run.pid]);
    assert_eq!(observed.exits(), vec![(run.pid, 0)]);
}
