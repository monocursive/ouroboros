#![cfg(target_os = "linux")]
//! J5-T: a child the supervisor did not start for the attempt is not the
//! attempt (jail-v1 §11.1 "Never stream unrelated host processes", §15 O04,
//! L01, L02).
//!
//! A shell that runs `exec ouro-jail … 3> >(jq …)` forks the process
//! substitution first and then replaces itself with the jail, so the jail
//! starts life with a child it never made. Any program can do the same (a
//! background job before `exec`, a library that spawns and then execs). The
//! ptrace observer ended on `waitpid(-1)` returning `ECHILD`, so that child
//! held it open until the deadline and was then counted as an unreaped child:
//! `doctor` reported `observer_closed_set` unavailable and every `run` with
//! observation refused with a false host diagnosis (125, `host_setup`). The
//! uncontained `none` supervisor, a child subreaper, classified the same
//! child as an escaped attempt process, recorded a membership escape and
//! killed it.
//!
//! What is checked, live on the reference host:
//!
//! - the tracer, in this test process, beside a child it did not trace:
//!   it finishes on its own account (every tracee reaped and the backend it
//!   reached the launcher through delivered), not on `ECHILD`; the other
//!   child's stop is not a tracee, its exit while traced is delivered as an
//!   untraced exit and is not loss, and a live one is left to its owner;
//! - the real `ouro-jail`, exec'd by a helper that already holds a live child
//!   (the process-substitution shape, made explicit rather than relying on a
//!   shell's exec optimisation): `doctor` reports the observer available; a
//!   strict `tool` run traced to that child settles verified with the whole
//!   stream delivered to it; `none` leaves it alone and loses nothing.
//!
//! Every process signalled is one this file started; every file is under a
//! private temporary directory.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use ouro_fixture::harness;
use ouro_jail::platform::linux::clock::Deadline;
use ouro_jail::platform::linux::exec::{self, FdMap};
use ouro_jail::platform::linux::probe::{self, ProbeStatus};
use ouro_jail::platform::linux::tracer::{
    self, ClosedOp, Tracer, TracerConfig, TracerEvent, TracerSummary,
};
use serde_json::Value;

mod common;

/// One tracer per process at a time: it owns every `waitpid` here.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The tracer is x86_64's (J5-D refuses elsewhere); these checks need it.
fn tracer_live() -> bool {
    if cfg!(target_arch = "x86_64") {
        return true;
    }
    harness::skip_or_fail("the ptrace observer implements the x86_64 closed set only");
    false
}

/// How long a tracer may take to say `Finished` once the traced tree is
/// over. Generous against host load; the foreign child lives far longer.
const FINISH_BOUND: Duration = Duration::from_secs(10);

// ===========================================================================
// The tracer, in this process
// ===========================================================================

/// A child of this process that is none of the tracer's business: `cat`,
/// blocked on a pipe only this test writes, so it lives exactly as long as
/// the test says.
struct Bystander {
    child: Child,
    stdin: Option<ChildStdin>,
    pid: libc::pid_t,
}

impl Bystander {
    fn start() -> Bystander {
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn /bin/cat");
        let stdin = child.stdin.take();
        let pid = libc::pid_t::try_from(child.id()).expect("a pid");
        Bystander { child, stdin, pid }
    }

    /// Alive, not a zombie, and still this process's child.
    fn alive_and_ours(&self) -> bool {
        let state = fs::read_to_string(format!("/proc/{}/stat", self.pid))
            .ok()
            .and_then(|raw| {
                raw.rsplit_once(')')
                    .and_then(|(_, tail)| tail.split_whitespace().next().map(str::to_owned))
            });
        let me = libc::pid_t::try_from(std::process::id()).expect("a pid");
        matches!(state.as_deref(), Some(s) if s != "Z") && tracer::ppid(self.pid) == Some(me)
    }

    /// Let it end: `cat` exits 0 at end of input.
    fn end(&mut self) {
        drop(self.stdin.take());
    }

    fn signal(&self, signal: libc::c_int) {
        // SAFETY: a child this test spawned and has not reaped.
        assert_eq!(
            unsafe { libc::kill(self.pid, signal) },
            0,
            "signal {signal}"
        );
    }
}

impl Drop for Bystander {
    fn drop(&mut self) {
        // End of input ends `cat`. It is waited for only while it is still
        // this process's child: once the tracer has reaped it, its number
        // may belong to anyone, and nothing is signalled or waited by it.
        drop(self.stdin.take());
        let me = libc::pid_t::try_from(std::process::id()).expect("a pid");
        if tracer::ppid(self.pid) == Some(me) {
            let _ = self.child.wait();
        }
    }
}

const RELEASE_FD: RawFd = 12;
const ERROR_FD: RawFd = 13;

/// The real inside launcher, `ouro-jail __launch --narrow`, with the target
/// `argv`, blocked on its release pipe.
struct Launcher {
    /// The pid to seize: the launcher itself.
    pid: libc::pid_t,
    /// The direct child of this process the launcher descends through, when
    /// it is not the launcher itself: bubblewrap's place in the real tree.
    backend: Option<libc::pid_t>,
    release: Option<OwnedFd>,
    _error: OwnedFd,
}

impl Launcher {
    /// The launcher as a direct child of this process: the `none` and
    /// probe shape.
    fn direct(target: &[&OsStr]) -> Launcher {
        let (release_r, release_w) = exec::pipe().expect("release pipe");
        let (error_r, error_w) = exec::pipe().expect("error pipe");
        let mut fds = FdMap::new();
        fds.add(release_r, RELEASE_FD).expect("place release");
        fds.add(error_w, ERROR_FD).expect("place error");
        let mut command = Command::new(harness::jail_path());
        command
            .args([
                "__launch",
                "--release-fd",
                "12",
                "--error-fd",
                "13",
                "--narrow",
                "--",
            ])
            .args(target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        fds.apply(&mut command);
        let child = command.spawn().expect("spawn the launcher");
        drop(fds);
        let pid = libc::pid_t::try_from(child.id()).expect("a pid");
        // The tracer reaps what it traces; the handle is not kept.
        drop(child);
        let launcher = Launcher {
            pid,
            backend: None,
            release: Some(release_w),
            _error: error_r,
        };
        launcher.await_blocked();
        launcher
    }

    /// The launcher one level down, under an untraced `sh` that waits for
    /// it and then outlives it by half a second before exiting 7: the
    /// contained shape, where bubblewrap is this process's child and the
    /// launcher's ancestor.
    fn beneath_a_backend(target: &[&OsStr]) -> Launcher {
        let script = r#""$@" & wait $!; sleep 0.5; exit 7"#;
        let (release_r, release_w) = exec::pipe().expect("release pipe");
        let (error_r, error_w) = exec::pipe().expect("error pipe");
        let mut fds = FdMap::new();
        fds.add(release_r, RELEASE_FD).expect("place release");
        fds.add(error_w, ERROR_FD).expect("place error");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script, "sh"])
            .arg(harness::jail_path())
            .args([
                "__launch",
                "--release-fd",
                "12",
                "--error-fd",
                "13",
                "--narrow",
                "--",
            ])
            .args(target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        fds.apply(&mut command);
        let child = command.spawn().expect("spawn the backend stand-in");
        drop(fds);
        let backend = libc::pid_t::try_from(child.id()).expect("a pid");
        drop(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        let pid = loop {
            if let Some(pid) = tracer::children(backend).into_iter().find(|pid| {
                tracer::cmdline(*pid)
                    .is_some_and(|argv| argv.get(1).map(Vec::as_slice) == Some(b"__launch"))
            }) {
                break pid;
            }
            assert!(
                Instant::now() < deadline,
                "the launcher never appeared under {backend}"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        let launcher = Launcher {
            pid,
            backend: Some(backend),
            release: Some(release_w),
            _error: error_r,
        };
        launcher.await_blocked();
        launcher
    }

    /// The attach contract: the launcher is blocked in `read(2)`.
    fn await_blocked(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let number = fs::read_to_string(format!("/proc/{}/syscall", self.pid))
                .ok()
                .and_then(|raw| {
                    raw.split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<i64>().ok())
                });
            if number == Some(libc::SYS_read) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the launcher {} never blocked",
                self.pid
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn release(&mut self) {
        let fd = self.release.take().expect("released once");
        fs::File::from(fd)
            .write_all(&[1])
            .expect("the release byte");
    }
}

/// What the tracer said, and when it said `Finished`.
struct Observed {
    events: Vec<TracerEvent>,
    finished_in: Option<Duration>,
    summary: TracerSummary,
}

impl Observed {
    fn gaps(&self) -> Vec<&TracerEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, TracerEvent::Gap { .. }))
            .collect()
    }

    fn untraced(&self) -> Vec<(libc::pid_t, i32)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                TracerEvent::UntracedChildExit { pid, status } => Some((*pid, *status)),
                _ => None,
            })
            .collect()
    }

    fn position(&self, pick: impl Fn(&TracerEvent) -> bool) -> Option<usize> {
        self.events.iter().position(pick)
    }

    fn opens_of(&self, path: &Path) -> usize {
        let want = path.as_os_str().as_encoded_bytes();
        self.events
            .iter()
            .filter(|e| {
                matches!(e, TracerEvent::Syscall { op: ClosedOp::Open, args, ret, .. }
                    if *ret >= 0 && args.path.as_ref().is_some_and(|p| p.bytes == want))
            })
            .count()
    }

    fn describe(&self) -> String {
        self.events
            .iter()
            .filter(|e| !matches!(e, TracerEvent::Fork { .. }))
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    }
}

/// Every event until `Finished` or `bound`, then the summary; whatever the
/// stop itself produces is kept too.
fn observe_until_finished(tracer: Tracer, started: Instant, bound: Duration) -> Observed {
    let mut events = Vec::new();
    let mut finished_in = None;
    let deadline = Instant::now() + bound;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tracer.events().recv_timeout(left) {
            Ok(TracerEvent::Finished) => {
                finished_in = Some(started.elapsed());
                events.push(TracerEvent::Finished);
                break;
            }
            Ok(event) => events.push(event),
            Err(_) => break,
        }
    }
    let summary = tracer.finish_within_draining(Duration::from_secs(5), |event| events.push(event));
    Observed {
        events,
        finished_in,
        summary,
    }
}

/// Read events until one matches, keeping all of them.
fn read_until(
    tracer: &Tracer,
    into: &mut Vec<TracerEvent>,
    bound: Duration,
    pick: impl Fn(&TracerEvent) -> bool,
) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        match tracer.events().recv_timeout(left) {
            Ok(event) => {
                let hit = pick(&event);
                into.push(event);
                if hit {
                    return true;
                }
            }
            Err(_) => return false,
        }
    }
}

/// A private directory with a FIFO the target waits on and the path it
/// creates once let through.
struct Gate {
    dir: tempfile::TempDir,
}

impl Gate {
    fn new() -> Gate {
        let dir = common::private_tempdir();
        let fifo = dir.path().join("gate");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("a path");
        // SAFETY: a NUL-terminated path this test owns.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
        Gate { dir }
    }

    fn fifo(&self) -> PathBuf {
        self.dir.path().join("gate")
    }

    fn created(&self) -> PathBuf {
        self.dir.path().join("created")
    }

    /// `sh` that reads one line from the FIFO (a read-only open, outside the
    /// closed set) and then creates `created` (an open that is in it).
    fn target(&self) -> Vec<OsString> {
        vec![
            "/bin/sh".into(),
            "-c".into(),
            r#"read x < "$1"; : > "$2""#.into(),
            "sh".into(),
            self.fifo().into_os_string(),
            self.created().into_os_string(),
        ]
    }

    /// Let the target through: open the FIFO for writing once it has a
    /// reader, without ever blocking past the deadline.
    fn open(&self) {
        let c = std::ffi::CString::new(self.fifo().as_os_str().as_encoded_bytes()).expect("a path");
        let deadline = Instant::now() + Duration::from_secs(10);
        let fd = loop {
            // SAFETY: a NUL-terminated path; the flags are plain ints.
            let fd = unsafe {
                libc::open(
                    c.as_ptr(),
                    libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd >= 0 {
                break fd;
            }
            assert!(
                Instant::now() < deadline,
                "the target never opened the gate"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        // SAFETY: just opened and owned here.
        let mut file = fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        file.write_all(b"go\n").expect("write the gate");
    }
}

fn as_os(argv: &[OsString]) -> Vec<&OsStr> {
    argv.iter().map(OsString::as_os_str).collect()
}

/// A child this process had before the tracer attached, and that outlives
/// the traced tree, is not the tracer's to wait for: `Finished` comes when
/// the tree is over, the child is still alive and still this process's own,
/// its stop and continue while traced are nobody's events, and nothing is
/// loss. The test then reaps it itself and gets its status, which proves the
/// tracer never took it.
#[test]
fn j5t_the_tracer_finishes_beside_a_live_child_it_does_not_trace() {
    let _serial = serial();
    if !tracer_live() {
        return;
    }
    let mut bystander = Bystander::start();
    let gate = Gate::new();
    let target = gate.target();
    let mut launcher = Launcher::direct(&as_os(&target));
    let tracer = Tracer::attach(launcher.pid, TracerConfig::default()).expect("attach");
    let started = Instant::now();
    launcher.release();
    // While the target waits on the gate: the bystander stops and
    // continues. Neither state change is a tracee's.
    bystander.signal(libc::SIGSTOP);
    std::thread::sleep(Duration::from_millis(50));
    bystander.signal(libc::SIGCONT);
    gate.open();
    let observed = observe_until_finished(tracer, started, FINISH_BOUND);
    println!(
        "j5t live: finished in {:?}; loss {:?}; unreaped {:?}; events:\n  {}",
        observed.finished_in,
        observed.summary.loss,
        observed.summary.unreaped_children,
        observed.describe()
    );
    assert!(
        observed.finished_in.is_some(),
        "the traced tree was over, but the tracer did not finish within {FINISH_BOUND:?}: \
         it waited for {} (a child it never traced) as if it were the tree",
        bystander.pid
    );
    assert_eq!(
        observed.opens_of(&gate.created()),
        1,
        "the one create was observed"
    );
    assert!(
        observed
            .events
            .iter()
            .any(|e| matches!(e, TracerEvent::Exit { pid, .. } if *pid == launcher.pid)),
        "the target's exit was observed"
    );
    assert!(observed.gaps().is_empty(), "no gap: {:?}", observed.gaps());
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
    assert!(
        observed.summary.unreaped_children.is_empty(),
        "a child the tracer does not answer for is not an unreaped child: {:?}",
        observed.summary.unreaped_children
    );
    assert!(
        !observed
            .untraced()
            .iter()
            .any(|(pid, _)| *pid == bystander.pid),
        "the bystander did not exit, so no exit of it can have been seen"
    );
    assert!(
        bystander.alive_and_ours(),
        "the bystander {} must be alive and this process's own after the tracer finished",
        bystander.pid
    );
    bystander.end();
    let status = bystander.child.wait().expect(
        "the bystander's status is still this process's to collect: the tracer never reaped it",
    );
    assert!(status.success(), "{status:?}");
}

/// The other half of "not lost": a child the tracer does not answer for that
/// ends while the tracer owns every `waitpid` is reaped there, and its status
/// reaches the consumer as an untraced exit — not as a gap, not as loss.
#[test]
fn j5t_a_child_it_does_not_trace_that_exits_while_traced_is_delivered_not_lost() {
    let _serial = serial();
    if !tracer_live() {
        return;
    }
    let mut bystander = Bystander::start();
    let gate = Gate::new();
    let target = gate.target();
    let mut launcher = Launcher::direct(&as_os(&target));
    let tracer = Tracer::attach(launcher.pid, TracerConfig::default()).expect("attach");
    let started = Instant::now();
    launcher.release();
    bystander.end();
    let mut early = Vec::new();
    let pid = bystander.pid;
    let seen = read_until(
        &tracer,
        &mut early,
        FINISH_BOUND,
        |e| matches!(e, TracerEvent::UntracedChildExit { pid: p, .. } if *p == pid),
    );
    gate.open();
    let mut observed = observe_until_finished(tracer, started, FINISH_BOUND);
    early.append(&mut observed.events);
    observed.events = early;
    println!("j5t exit: events:\n  {}", observed.describe());
    assert!(
        seen,
        "the bystander's exit reached the consumer while traced"
    );
    let statuses: Vec<i32> = observed
        .untraced()
        .into_iter()
        .filter(|(p, _)| *p == pid)
        .map(|(_, status)| status)
        .collect();
    assert_eq!(statuses.len(), 1, "exactly one exit of it: {statuses:?}");
    assert!(
        libc::WIFEXITED(statuses[0]) && libc::WEXITSTATUS(statuses[0]) == 0,
        "its own status, exit 0: {:#x}",
        statuses[0]
    );
    assert!(observed.finished_in.is_some(), "the tracer finished");
    assert_eq!(observed.opens_of(&gate.created()), 1);
    assert!(observed.gaps().is_empty(), "no gap: {:?}", observed.gaps());
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
    assert!(observed.summary.unreaped_children.is_empty());
    // Its one route was the tracer's event: this process can no longer
    // collect it.
    assert!(
        bystander.child.try_wait().is_err(),
        "already reaped by the tracer"
    );
}

/// What the tracer does answer for besides its tracees: the child of this
/// process it reached the launcher through — bubblewrap in the real tree,
/// here an `sh` that outlives the launcher by half a second and exits 7.
/// Its exit is delivered before `Finished`, even with a bystander alive
/// throughout, which the tracer does not wait for.
#[test]
fn j5t_the_backend_the_launcher_descends_through_is_awaited_and_delivered() {
    let _serial = serial();
    if !tracer_live() {
        return;
    }
    let bystander = Bystander::start();
    let gate = Gate::new();
    let target = gate.target();
    let mut launcher = Launcher::beneath_a_backend(&as_os(&target));
    let backend = launcher.backend.expect("a backend");
    let tracer = Tracer::attach(launcher.pid, TracerConfig::default()).expect("attach");
    let started = Instant::now();
    launcher.release();
    gate.open();
    let observed = observe_until_finished(tracer, started, FINISH_BOUND);
    println!(
        "j5t backend: finished in {:?}; loss {:?}; unreaped {:?}; events:\n  {}",
        observed.finished_in,
        observed.summary.loss,
        observed.summary.unreaped_children,
        observed.describe()
    );
    assert!(
        observed.finished_in.is_some(),
        "the tree and its backend ended; the tracer must finish without waiting for \
         the bystander {}",
        bystander.pid
    );
    let exit = observed
        .position(|e| matches!(e, TracerEvent::UntracedChildExit { pid, .. } if *pid == backend))
        .unwrap_or_else(|| panic!("the backend {backend}'s exit was never delivered"));
    let finished = observed
        .position(|e| matches!(e, TracerEvent::Finished))
        .expect("finished");
    assert!(
        exit < finished,
        "the backend's exit is delivered before Finished"
    );
    let (_, status) = observed.untraced()[observed
        .untraced()
        .iter()
        .position(|(pid, _)| *pid == backend)
        .expect("the backend's exit")];
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 7,
        "the backend's own status, exit 7: {status:#x}"
    );
    assert_eq!(observed.opens_of(&gate.created()), 1);
    assert!(observed.gaps().is_empty(), "no gap: {:?}", observed.gaps());
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
    assert!(observed.summary.unreaped_children.is_empty());
    assert!(bystander.alive_and_ours(), "the bystander was left alone");
}

/// The target forks children that exit at once, waits until every one is
/// a zombie, and exits without reaping them.
const ORPHANS: &str = r#"
import os, sys, time
pids = []
for _ in range(int(sys.argv[1])):
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    pids.append(pid)
def zombie(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        return False
deadline = time.monotonic() + 20
while not all(zombie(pid) for pid in pids):
    if time.monotonic() > deadline:
        sys.exit(3)
    time.sleep(0.01)
os._exit(0)
"#;

/// J5-T w3 (L01.7 under `none`): a child this process gains after the
/// tracer attached is the attempt's, not a bystander's. A tracee's children
/// that exit before it are reaped by the tracer only as tracees: their
/// zombies stay for the real parent, and when it exits without waiting they
/// pass to the nearest subreaper — the `none` supervisor, here this test
/// process. The tracer reaps every one before it finishes, and still does
/// not wait for the bystander it was attached beside.
#[test]
fn j5t_orphans_adopted_while_traced_are_reaped_before_finished() {
    const N: usize = 8;
    let _serial = serial();
    if !tracer_live() {
        return;
    }
    let me = libc::pid_t::try_from(std::process::id()).expect("a pid");
    let bystander = Bystander::start();
    // SAFETY: prctl with integer arguments only; undone below.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let n = N.to_string();
    let target: Vec<&OsStr> = ["/usr/bin/python3", "-c", ORPHANS, n.as_str()]
        .into_iter()
        .map(OsStr::new)
        .collect();
    let mut launcher = Launcher::direct(&target);
    let tracer = Tracer::attach(launcher.pid, TracerConfig::default()).expect("attach");
    let started = Instant::now();
    launcher.release();
    let observed = observe_until_finished(tracer, started, FINISH_BOUND);
    let left: Vec<(libc::pid_t, Option<String>)> = tracer::children(me)
        .into_iter()
        .filter(|pid| *pid != bystander.pid)
        .map(|pid| {
            let state = fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|raw| {
                    raw.rsplit_once(')')
                        .and_then(|(_, tail)| tail.split_whitespace().next().map(str::to_owned))
                });
            (pid, state)
        })
        .collect();
    // Whatever the tracer left is this test's to reap, never anyone else's.
    for (pid, _) in &left {
        let mut status = 0;
        // SAFETY: `pid` is this process's own child.
        unsafe { libc::waitpid(*pid, &raw mut status, libc::WNOHANG) };
    }
    // SAFETY: as above.
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) };
    println!(
        "j5t orphans: finished in {:?}; left {left:?}; loss {:?}; untraced exits {}",
        observed.finished_in,
        observed.summary.loss,
        observed.untraced().len()
    );
    assert!(observed.finished_in.is_some(), "the tracer finished");
    assert!(
        observed
            .events
            .iter()
            .any(|e| matches!(e, TracerEvent::Exit { pid, status, .. }
                if *pid == launcher.pid && libc::WIFEXITED(*status) && libc::WEXITSTATUS(*status) == 0)),
        "the target made its {N} zombies and exited 0: {}",
        observed.describe()
    );
    assert!(
        left.is_empty(),
        "the tracer finished leaving {} adopted orphan(s) unreaped: {left:?}",
        left.len()
    );
    assert_eq!(
        observed.untraced().len(),
        N,
        "each orphan's zombie reaped here, as an untraced child"
    );
    assert!(observed.gaps().is_empty(), "no gap: {:?}", observed.gaps());
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
    assert!(observed.summary.unreaped_children.is_empty());
    assert!(bystander.alive_and_ours(), "the bystander was left alone");
}

// ===========================================================================
// The real `ouro-jail`, exec'd beside a child it did not start
// ===========================================================================

/// The descriptor the inherited reader holds the other end of.
const TRACE_FD: RawFd = 3;

/// What the child the jail inherits does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Foreign {
    /// Blocks on a pipe the test holds (`sleep 30 & exec ouro-jail …`).
    Hold,
    /// Reads the jail's `--trace-fd 3` to its end into a file and then
    /// writes `eof` to another: `exec ouro-jail … 3> >(cat > copy)`.
    TraceReader,
    /// Exits by itself after 300 ms, while the jail is running.
    ExitsSoon,
}

/// The jail's run and the child it was exec'd beside.
struct Beside {
    captured: exec::Captured,
    foreign: libc::pid_t,
    birth: Option<u64>,
    hold: Option<OwnedFd>,
    dir: PathBuf,
    _keep: tempfile::TempDir,
}

impl Beside {
    /// Still the process that was forked (same birth), and not a zombie.
    fn foreign_alive(&self) -> bool {
        let Ok(raw) = fs::read_to_string(format!("/proc/{}/stat", self.foreign)) else {
            return false;
        };
        let state = raw
            .rsplit_once(')')
            .and_then(|(_, tail)| tail.split_whitespace().next().map(str::to_owned));
        tracer::start_ticks(self.foreign) == self.birth && state.as_deref() != Some("Z")
    }

    /// Let a `Hold` child go, and wait (bounded) until it has ended.
    fn release(&mut self) {
        drop(self.hold.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.foreign_alive() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// `eof` once the reader saw the end of the stream, bounded.
    fn reader_finished(&self) -> bool {
        let done = self.dir.join("reader-done");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if fs::read_to_string(&done).is_ok_and(|text| text == "eof\n") {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn trace_copy(&self) -> Vec<Value> {
        fs::read_to_string(self.dir.join("trace-copy"))
            .expect("the reader's copy")
            .lines()
            .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}")))
            .collect()
    }

    fn receipt(&self) -> Value {
        let raw = fs::read(self.dir.join("receipt.json")).unwrap_or_else(|e| {
            panic!(
                "no receipt ({e}); exit {:?}, stderr:\n{}",
                self.captured.code(),
                self.captured.stderr
            )
        });
        serde_json::from_slice(&raw).expect("receipt JSON")
    }
}

impl Drop for Beside {
    fn drop(&mut self) {
        // A `Hold` child ends at EOF on its pipe; nothing is signalled.
        drop(self.hold.take());
    }
}

/// `fd` moved above the low numbers, close-on-exec, so no descriptor this
/// helper passes on can collide with the fixed `TRACE_FD`.
fn high(fd: OwnedFd) -> OwnedFd {
    // SAFETY: duplicating an owned descriptor; the result is owned below.
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 100) };
    assert!(
        raw >= 100,
        "F_DUPFD_CLOEXEC: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: just created and owned by nothing else.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

/// The foreign child: forked by the process that is about to become the
/// jail, before its `exec`. It never execs and calls only async-signal-safe
/// functions (`dup2`, `close_range`, `read`, `write`, `nanosleep`, `_exit`).
///
/// # Safety
/// Runs in a child forked from a multi-threaded process.
unsafe fn foreign_main(mode: Foreign, hold: RawFd, trace: RawFd, copy: RawFd, done: RawFd) -> ! {
    unsafe {
        match mode {
            Foreign::Hold => {
                libc::dup2(hold, 0);
                libc::syscall(libc::SYS_close_range, 1u32, u32::MAX, 0u32);
            }
            Foreign::TraceReader => {
                libc::dup2(trace, 0);
                libc::dup2(copy, 1);
                libc::dup2(done, 2);
                libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
            }
            Foreign::ExitsSoon => {
                libc::syscall(libc::SYS_close_range, 0u32, u32::MAX, 0u32);
                let pause = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 300_000_000,
                };
                libc::nanosleep(&raw const pause, std::ptr::null_mut());
                libc::_exit(0);
            }
        }
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::read(0, buf.as_mut_ptr().cast(), buf.len());
            if n > 0 {
                if mode == Foreign::TraceReader {
                    let mut written = 0;
                    let n = n as usize;
                    while written < n {
                        let w = libc::write(1, buf[written..].as_ptr().cast(), n - written);
                        if w <= 0 {
                            libc::_exit(1);
                        }
                        written += w as usize;
                    }
                }
                continue;
            }
            if n < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            break;
        }
        if mode == Foreign::TraceReader {
            libc::write(2, b"eof\n".as_ptr().cast(), 4);
        }
        libc::_exit(0);
    }
}

/// Exec `ouro-jail <args>` from a process that forked `foreign` first, the
/// way `exec` after a process substitution or a background job does, with
/// private state, the workspace and `--receipt` under a private directory.
/// With [`Foreign::TraceReader`], `--trace-fd 3` is the reader's pipe.
fn run_beside(foreign: Foreign, args: &[&str], target: &[&str]) -> Beside {
    let keep = common::private_tempdir();
    let dir = keep.path().to_path_buf();
    for name in ["data", "config", "workspace"] {
        fs::create_dir(dir.join(name)).expect("private dirs");
        fs::set_permissions(
            dir.join(name),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("0700");
    }
    let (report_r, report_w) = exec::pipe().expect("report pipe");
    let (hold_r, hold_w) = exec::pipe().expect("hold pipe");
    let (trace_r, trace_w) = exec::pipe().expect("trace pipe");
    let copy = OwnedFd::from(fs::File::create(dir.join("trace-copy")).expect("copy"));
    let done = OwnedFd::from(fs::File::create(dir.join("reader-done")).expect("done"));
    let (report_w, hold_r, trace_r, trace_w, copy, done) = (
        high(report_w),
        high(hold_r),
        high(trace_r),
        high(trace_w),
        high(copy),
        high(done),
    );
    let raw = (
        report_w.as_raw_fd(),
        hold_r.as_raw_fd(),
        trace_r.as_raw_fd(),
        trace_w.as_raw_fd(),
        copy.as_raw_fd(),
        done.as_raw_fd(),
    );

    let mut argv: Vec<OsString> = args.iter().map(OsString::from).collect();
    if foreign == Foreign::TraceReader {
        argv.push("--trace-fd".into());
        argv.push(TRACE_FD.to_string().into());
    }
    if args.first() == Some(&"run") {
        argv.push("--receipt".into());
        argv.push(dir.join("receipt.json").into_os_string());
    }
    if !target.is_empty() {
        argv.push("--".into());
        argv.extend(target.iter().map(OsString::from));
    }
    let mut command = Command::new(harness::jail_path());
    command
        .args(&argv)
        .current_dir(dir.join("workspace"))
        .env("OURO_DATA_DIR", dir.join("data"))
        .env("OURO_CONFIG_DIR", dir.join("config"))
        .stdin(Stdio::null());
    // SAFETY: between fork and exec: `signal`, `fork`, `write`, `dup2` and
    // `fcntl` are async-signal-safe, the foreign child runs only
    // `foreign_main`, and every descriptor was opened before the fork.
    unsafe {
        command.pre_exec(move || {
            let (report_w, hold_r, trace_r, trace_w, copy, done) = raw;
            // As the harness: the jail starts with INT, QUIT and HUP at
            // their defaults whatever launched the suite.
            for signal in [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP] {
                libc::signal(signal, libc::SIG_DFL);
            }
            let pid = libc::fork();
            if pid < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if pid == 0 {
                foreign_main(foreign, hold_r, trace_r, copy, done);
            }
            let bytes = pid.to_ne_bytes();
            if libc::write(report_w, bytes.as_ptr().cast(), bytes.len()) != 4 {
                return Err(std::io::Error::last_os_error());
            }
            if foreign == Foreign::TraceReader && libc::dup2(trace_w, TRACE_FD) != TRACE_FD {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ouro-jail");
    drop((report_w, hold_r, trace_r, trace_w, copy, done));
    let mut pid_bytes = [0u8; 4];
    std::io::Read::read_exact(&mut fs::File::from(report_r), &mut pid_bytes)
        .expect("the foreign child's pid");
    let foreign_pid = libc::pid_t::from_ne_bytes(pid_bytes);
    let birth = tracer::start_ticks(foreign_pid);
    let captured = exec::finish_captured(child, Deadline::after(Duration::from_secs(120)))
        .expect("the jail ran");
    Beside {
        captured,
        foreign: foreign_pid,
        birth,
        hold: Some(hold_w),
        dir,
        _keep: keep,
    }
}

/// `none` needs a delegated leaf (§9.3); the conformance run provides it.
fn none_live() -> bool {
    let leaf = probe::run_one(
        "cgroup_delegated_leaf",
        &harness::jail_path(),
        Path::new("bwrap"),
    );
    if leaf.status != ProbeStatus::Available {
        harness::skip_or_fail(&format!(
            "`none` needs a delegated user scope: {}",
            leaf.evidence
        ));
        return false;
    }
    true
}

fn capability<'a>(doctor: &'a Value, name: &str) -> &'a Value {
    doctor["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {name} in {doctor:#}"))
}

/// Every coverage class of an observed, clean attempt: active, no gap.
fn assert_no_coverage_gap(receipt: &Value, label: &str) {
    let coverage = receipt["coverage"].as_object().expect("coverage");
    for (class, entry) in coverage {
        if entry["status"] == "unsupported" {
            continue;
        }
        assert_eq!(entry["status"], "active", "{label}: {class}: {entry:#}");
        assert!(
            entry["gaps"].as_array().is_none_or(Vec::is_empty),
            "{label}: {class}: {entry:#}"
        );
    }
}

/// The observer probe `doctor` runs is the same tracer: a child `doctor`
/// was exec'd beside is not a host that lacks ptrace.
#[test]
fn j5t_doctor_reports_the_observer_available_beside_an_inherited_child() {
    let _serial = serial();
    if !common::live() || !tracer_live() {
        return;
    }
    let mut beside = run_beside(Foreign::Hold, &["doctor", "--json"], &[]);
    let doctor: Value = serde_json::from_str(&beside.captured.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: stdout {:?} stderr {:?}",
            beside.captured.stdout, beside.captured.stderr
        )
    });
    let probe = capability(&doctor, "observer_closed_set");
    let observation = capability(&doctor, "closed_set_observation");
    println!("j5t doctor: {probe}\n{observation}");
    assert_eq!(probe["status"], "available", "{probe:#}");
    assert_eq!(observation["status"], "available", "{observation:#}");
    assert!(
        beside.foreign_alive(),
        "doctor left the inherited child alone"
    );
    beside.release();
    assert!(!beside.foreign_alive(), "and it ends when let go");
}

/// The reported shape: a strict `tool` run whose trace goes to the child it
/// was exec'd beside. It runs, settles with the tree verified and nothing
/// lost, and that child reads the whole stream to the end, which is the
/// final receipt's (§13.3).
#[test]
fn j5t_a_strict_tool_run_traced_to_an_inherited_reader_settles_verified() {
    let _serial = serial();
    if !common::live() || !tracer_live() {
        return;
    }
    let created = "created-by-target";
    let beside = run_beside(
        Foreign::TraceReader,
        &["run", "--profile", "tool", "--evidence", "strict"],
        &["/bin/sh", "-c", &format!(": > {created}")],
    );
    println!(
        "j5t tool: exit {:?}\nstderr:\n{}",
        beside.captured.code(),
        beside.captured.stderr
    );
    assert_eq!(
        beside.captured.code(),
        Some(0),
        "the run must not be refused or degraded by the child it was exec'd beside: {}",
        beside.captured.stderr
    );
    let receipt = beside.receipt();
    common::assert_semantic_receipt(&receipt);
    assert_eq!(receipt["phase"], "settled", "{receipt:#}");
    assert_eq!(
        receipt["outcome"]["kind"], "exited",
        "{:#}",
        receipt["outcome"]
    );
    assert_eq!(receipt["outcome"]["code"], 0);
    assert_eq!(
        receipt["errors"],
        serde_json::json!([]),
        "{:#}",
        receipt["errors"]
    );
    assert_eq!(
        receipt["lifetime"]["tree_empty"], true,
        "{:#}",
        receipt["lifetime"]
    );
    assert_eq!(
        receipt["lifetime"]["integrity"], "verified",
        "{:#}",
        receipt["lifetime"]
    );
    assert_no_coverage_gap(&receipt, "tool");
    assert!(
        beside.dir.join("workspace").join(created).exists(),
        "the target ran"
    );
    assert!(
        beside.reader_finished(),
        "the inherited reader saw the end of the stream"
    );
    let events = beside.trace_copy();
    assert!(!events.is_empty(), "the inherited reader got the stream");
    common::check_trace(&events, Some(&receipt)).expect("the whole stream, ending in the receipt");
}

/// `none` is a child subreaper and walks its own children to find escaped
/// attempt processes. A child it was exec'd beside is not one: it is not
/// signalled, not reaped, and not a membership escape, whether it lives
/// through the attempt or ends during it, with observation on or off.
fn none_case(observe: &str, foreign: Foreign) {
    let _serial = serial();
    if !common::live() || !tracer_live() || !none_live() {
        return;
    }
    let label = format!("none/observe {observe}/{foreign:?}");
    let mut beside = run_beside(
        foreign,
        &[
            "run",
            "--profile",
            "none",
            "--observe",
            observe,
            "--evidence",
            "strict",
        ],
        &["/bin/sh", "-c", "sleep 1"],
    );
    println!(
        "j5t {label}: exit {:?}\nstderr:\n{}",
        beside.captured.code(),
        beside.captured.stderr
    );
    let alive_after = beside.foreign_alive();
    let reader_done = foreign != Foreign::TraceReader || beside.reader_finished();
    assert_eq!(
        beside.captured.code(),
        Some(0),
        "{label}: the attempt must not be refused because of a child it did not start: {}",
        beside.captured.stderr
    );
    let receipt = beside.receipt();
    common::assert_semantic_receipt(&receipt);
    assert_eq!(receipt["phase"], "settled", "{label}: {receipt:#}");
    assert_eq!(receipt["outcome"]["kind"], "exited", "{label}");
    assert_eq!(
        receipt["errors"],
        serde_json::json!([]),
        "{label}: {:#}",
        receipt["errors"]
    );
    assert_ne!(
        receipt["lifetime"]["integrity"], "lost",
        "{label}: an inherited child is not a membership escape: {:#}",
        receipt["lifetime"]
    );
    assert_eq!(
        receipt["lifetime"]["tree_empty"], true,
        "{label}: {:#}",
        receipt["lifetime"]
    );
    if observe == "on" {
        assert_no_coverage_gap(&receipt, &label);
    }
    match foreign {
        Foreign::Hold => {
            assert!(alive_after, "{label}: the inherited child was killed");
            beside.release();
        }
        Foreign::TraceReader => {
            assert!(
                reader_done,
                "{label}: the inherited reader was killed before EOF"
            );
            common::check_trace(&beside.trace_copy(), Some(&receipt))
                .unwrap_or_else(|e| panic!("{label}: {e}"));
        }
        Foreign::ExitsSoon => {}
    }
}

#[test]
fn j5t_none_leaves_an_inherited_child_alone_observed() {
    none_case("on", Foreign::Hold);
}

#[test]
fn j5t_none_leaves_an_inherited_child_alone_unobserved() {
    none_case("off", Foreign::Hold);
}

#[test]
fn j5t_none_traced_to_an_inherited_reader_delivers_the_whole_stream() {
    none_case("on", Foreign::TraceReader);
}

/// With observation off `none` reaps its own exited children and checks
/// where each died; one that was never the attempt's, ending mid-run, is
/// not a membership escape.
#[test]
fn j5t_none_unobserved_an_inherited_child_ending_mid_run_is_not_an_escape() {
    none_case("off", Foreign::ExitsSoon);
}
