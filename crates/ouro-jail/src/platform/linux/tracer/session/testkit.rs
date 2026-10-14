//! What the session's unit tests share: a scripted `/proc`, the one way to
//! build a session, and the helpers that plant and read its state.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, MutexGuard};

use libc::pid_t;

use super::restart::{Awaiting, Site};
use super::seams::ProcView;
use super::tasks::{Call, Pending, Task, TaskState};
use super::{Handles, Session};
use crate::platform::linux::tracer::closed_set;
use crate::platform::linux::tracer::{
    Args, CandidateImage, GapReason, KernelImage, OpSet, PathSnapshot, ShebangImage, TracerConfig,
    TracerEvent, sys,
};

/// `/proc` as a test scripts it. Every read answers from here, never from
/// the real `/proc`, and what the script does not name reads as absent.
#[derive(Default)]
pub(super) struct Script {
    /// `tid -> (tgid, start ticks)`.
    pub(super) tasks: HashMap<pid_t, (pid_t, u64)>,
    /// `pid -> the parent it reports`.
    pub(super) parents: HashMap<pid_t, pid_t>,
    /// The children of this process, whichever pid is asked about.
    pub(super) children: Vec<pid_t>,
    pub(super) cmdline: HashMap<pid_t, Vec<u8>>,
    /// `/proc/<tid>/exe` links.
    pub(super) exe: HashMap<pid_t, Vec<u8>>,
    /// `#!` lines by candidate path.
    pub(super) scripts: HashMap<Vec<u8>, ShebangImage>,
    /// `/proc/<tid>/cwd` links.
    pub(super) cwd: HashMap<pid_t, Vec<u8>>,
    /// `/proc/<tid>/fd/<fd>` links, with the link count of the file
    /// each resolves to when the script gives one.
    pub(super) fds: HashMap<(pid_t, i64), (Vec<u8>, Option<u64>)>,
    /// How many times each kind of read was made.
    pub(super) reads: HashMap<&'static str, usize>,
}

/// One script, shared by the session that reads it and the test that
/// edits it while the session runs: a recycled pid, a reaped backend.
#[derive(Clone, Default)]
pub(super) struct FakeProc(Arc<Mutex<Script>>);

impl FakeProc {
    /// With `tid`, a thread of `tgid` started at `ticks`.
    pub(super) fn task(self, tid: pid_t, tgid: pid_t, ticks: u64) -> FakeProc {
        self.edit(|script| {
            script.tasks.insert(tid, (tgid, ticks));
        });
        self
    }

    pub(super) fn edit(&self, change: impl FnOnce(&mut Script)) {
        change(&mut self.0.lock().unwrap());
    }

    /// How many times each kind of read was made since the script began,
    /// or since a test cleared the count.
    pub(super) fn reads(&self) -> HashMap<&'static str, usize> {
        self.0.lock().unwrap().reads.clone()
    }

    /// The script, counting one read of `file`.
    pub(super) fn read(&self, file: &'static str) -> MutexGuard<'_, Script> {
        let mut script = self.0.lock().unwrap();
        *script.reads.entry(file).or_default() += 1;
        script
    }
}

impl ProcView for FakeProc {
    fn tgid(&self, tid: pid_t) -> Option<pid_t> {
        self.read("tgid").tasks.get(&tid).map(|(tgid, _)| *tgid)
    }
    fn start_ticks(&self, tid: pid_t) -> Option<u64> {
        self.read("start_ticks")
            .tasks
            .get(&tid)
            .map(|(_, ticks)| *ticks)
    }
    fn ppid(&self, pid: pid_t) -> Option<pid_t> {
        self.read("ppid").parents.get(&pid).copied()
    }
    fn children(&self, _pid: pid_t) -> Vec<pid_t> {
        self.read("children").children.clone()
    }
    fn cmdline(&self, tid: pid_t) -> Option<Vec<u8>> {
        self.read("cmdline").cmdline.get(&tid).cloned()
    }
    fn kernel_image(&self, tid: pid_t, images: &[Vec<u8>]) -> Option<KernelImage> {
        self.read("exe").exe.get(&tid).map(|path| KernelImage {
            path: path.clone(),
            identity: None,
            candidates: images
                .iter()
                .map(|path| CandidateImage {
                    path: path.clone(),
                    identity: None,
                })
                .collect(),
        })
    }
    fn script_image(&self, _tid: pid_t, candidate: &[u8]) -> Option<ShebangImage> {
        self.read("script").scripts.get(candidate).cloned()
    }
    fn cwd(&self, tid: pid_t) -> Option<Vec<u8>> {
        self.read("cwd").cwd.get(&tid).cloned()
    }
    fn fd_link(&self, tid: pid_t, fd: i64) -> Option<Vec<u8>> {
        self.read("fd")
            .fds
            .get(&(tid, fd))
            .map(|(link, _)| link.clone())
    }
    fn fd_nlink(&self, tid: pid_t, fd: i64) -> Option<u64> {
        self.read("fd_nlink")
            .fds
            .get(&(tid, fd))
            .and_then(|(_, nlink)| *nlink)
    }
}

/// The one way a unit test builds a session: `config`, `/proc` as
/// `procfs` plays it, and a handoff channel `depth` events deep whose
/// receiver the test reads, or drops to play a consumer that never does.
pub(super) fn new_session(
    config: TracerConfig,
    procfs: impl ProcView + 'static,
    depth: usize,
) -> (Session, Receiver<TracerEvent>) {
    let (tx, rx) = std::sync::mpsc::sync_channel(depth);
    (
        Session::new(config, tx, Arc::default(), 0, Box::new(procfs)),
        rx,
    )
}

/// A session over `proc` with every task it scripts registered, in tid
/// order, as their first stops would register them.
pub(super) fn traced(config: TracerConfig, proc: &FakeProc) -> (Session, Receiver<TracerEvent>) {
    let mut tids: Vec<pid_t> = proc.0.lock().unwrap().tasks.keys().copied().collect();
    tids.sort_unstable();
    let (mut session, rx) = new_session(config, proc.clone(), 64);
    for tid in tids {
        session.register(tid);
    }
    (session, rx)
}

/// A session whose consumer never reads: the handoff holds one event.
pub(super) fn stalled_session() -> (Session, Receiver<TracerEvent>) {
    let config = TracerConfig {
        queue_bytes_max: 64 * 1024 * 1024,
        ..TracerConfig::default()
    };
    new_session(config, FakeProc::default(), 1)
}

/// What `finish` is handed once the supervisor has asked the tracer to
/// stop: the stop flag, already set, ends the terminal drain at once.
pub(super) fn stopped(session: &Session) -> Handles {
    Handles {
        stop: Arc::new(AtomicBool::new(true)),
        shutdown_ns: Arc::default(),
        tid: Arc::default(),
        handed: Arc::clone(&session.handed),
    }
}

/// A complete pathname snapshot.
pub(super) fn snapshot(path: &[u8]) -> PathSnapshot {
    PathSnapshot {
        bytes: path.to_vec(),
        complete: true,
    }
}

/// Make `pending` the call `tid` has in flight, as its entry stop would.
pub(super) fn plant(session: &mut Session, tid: pid_t, pending: Pending) {
    assert!(idle(session, tid), "a registered task between calls");
    session
        .tasks
        .begin_call(tid, Call::Closed(pending), Site::default(), false);
}

/// Whether `tid` is between calls, with nothing in flight.
pub(super) fn idle(session: &Session, tid: pid_t) -> bool {
    matches!(
        session.tasks.get(tid).map(Task::state),
        Some(TaskState::Idle)
    )
}

/// A pid no real task can have (above `PID_MAX_LIMIT`), so the ptrace
/// calls the handlers make on it fail with ESRCH and touch nothing.
pub(super) const RECYCLED: pid_t = 5_000_001;
pub(super) const WORKER: pid_t = 5_000_002;

/// Make a call of syscall `nr` on `path` the one `tid` has in flight.
pub(super) fn pend(session: &mut Session, tid: pid_t, nr: u64, path: &str) {
    let entry = closed_set::lookup(nr).expect("a closed-set row");
    let args = Args {
        path: Some(snapshot(path.as_bytes())),
        ..Args::default()
    };
    plant(session, tid, Pending::new(entry, args, [0; 6]));
}

pub(super) fn drained(rx: &Receiver<TracerEvent>, session: &mut Session) -> Vec<TracerEvent> {
    session.flush();
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        out.push(event);
        session.flush();
    }
    out
}

pub(super) fn waiting(session: &mut Session, tid: pid_t, nr: u64, path: &str) {
    pend(session, tid, nr, path);
    session.handle_exit(tid, -sys::ERESTARTSYS);
}

/// A handler's entry has just said "restarted": by the frame, or by the
/// restart code alone.
pub(super) fn announced(session: &mut Session, tid: pid_t, by_kernel: bool) {
    waiting(session, tid, libc::SYS_openat as u64, "/w/fifo");
    let wait = session.tasks.wait_mut(tid).expect("a restart wait");
    wait.awaiting = Awaiting::Reentry { by_kernel };
}

pub(super) const LEADER: pid_t = 5_000_011;
pub(super) const PEER: pid_t = 5_000_012;

/// A thread group of two: its leader, and a peer thread.
pub(super) fn leader_and_peer() -> FakeProc {
    FakeProc::default()
        .task(LEADER, LEADER, 1000)
        .task(PEER, LEADER, 1000)
}

/// A child of this test, seized by the calling thread, that has the
/// narrowing filter installed and makes one `mkdir` of `path` when
/// released (or, from [`Mkdirer::start_open`], one `openat(path,
/// O_WRONLY)`): its first stop is that call's seccomp entry stop.
pub(super) struct Mkdirer {
    pub(super) pid: pid_t,
    go: libc::c_int,
}

impl Mkdirer {
    /// `None` when this host will not let a test trace its own child.
    pub(super) fn start(path: &std::ffi::CStr) -> Option<Mkdirer> {
        Mkdirer::start_call(path, false)
    }

    /// The same child making `openat(path, O_WRONLY)`: on a FIFO nobody
    /// reads, it sleeps inside the call.
    pub(super) fn start_open(path: &std::ffi::CStr) -> Option<Mkdirer> {
        Mkdirer::start_call(path, true)
    }

    pub(super) fn start_call(path: &std::ffi::CStr, open: bool) -> Option<Mkdirer> {
        let mut fds: [libc::c_int; 2] = [0; 2];
        // SAFETY: `pipe2` writes two descriptors into the live array.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: the child runs only async-signal-safe code — `close`,
        // the allocation-free filter install, `read`, one raw syscall
        // with a pointer prepared before the fork, and `_exit` — so the
        // other threads of this test process cannot matter to it.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: as above; every pointer is live in the child's copy
            // of this address space.
            unsafe {
                libc::close(fds[1]);
                if crate::platform::linux::tracer::filter::install_narrowing_filter_for(
                    crate::platform::linux::tracer::NARROWING_TRACE_DATA,
                    true,
                )
                .is_err()
                {
                    libc::_exit(3);
                }
                let mut byte = 0u8;
                libc::read(fds[0], (&raw mut byte).cast::<libc::c_void>(), 1);
                if open {
                    libc::syscall(
                        libc::SYS_openat,
                        libc::AT_FDCWD,
                        path.as_ptr(),
                        libc::O_WRONLY | libc::O_CLOEXEC,
                    );
                } else {
                    // aarch64 has no `mkdir` syscall of its own: the same
                    // call goes through `mkdirat` there.
                    #[cfg(target_arch = "x86_64")]
                    libc::syscall(libc::SYS_mkdir, path.as_ptr(), 0o700);
                    #[cfg(not(target_arch = "x86_64"))]
                    libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, path.as_ptr(), 0o700);
                }
                libc::_exit(0);
            }
        }
        assert!(pid > 0, "fork: {}", std::io::Error::last_os_error());
        // SAFETY: the read end belongs to the child now.
        unsafe { libc::close(fds[0]) };
        let child = Mkdirer { pid, go: fds[1] };
        if let Err(err) = sys::seize(pid, sys::SEIZE_OPTIONS) {
            ouro_fixture::harness::skip_or_fail(&format!(
                "this host will not let a test trace its own child: {err}"
            ));
            return None;
        }
        Some(child)
    }

    /// Release the child and return the status of its first stop.
    pub(super) fn release(&self) -> libc::c_int {
        // SAFETY: one byte from a live buffer to a descriptor we own.
        let written = unsafe { libc::write(self.go, b"g".as_ptr().cast::<libc::c_void>(), 1) };
        assert_eq!(written, 1);
        self.wait()
    }

    /// The next status of this child only: never `waitpid(-1)`, which
    /// would take another test's children.
    pub(super) fn wait(&self) -> libc::c_int {
        let mut status = 0;
        // SAFETY: `waitpid` writes one int through a live pointer.
        let got = unsafe { libc::waitpid(self.pid, &raw mut status, libc::__WALL) };
        assert_eq!(got, self.pid, "{}", std::io::Error::last_os_error());
        status
    }

    pub(super) fn kill(&self) {
        // SAFETY: a pid this test created, and a valid signal.
        assert_eq!(unsafe { libc::kill(self.pid, libc::SIGKILL) }, 0);
    }

    /// Hand every remaining status to the session until the child is
    /// reaped.
    pub(super) fn reap_into(&self, session: &mut Session) {
        loop {
            let status = self.wait();
            session.handle(self.pid, status);
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return;
            }
        }
    }
}

impl Drop for Mkdirer {
    fn drop(&mut self) {
        // SAFETY: our own pid and descriptor; both calls tolerate either
        // being already gone.
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
            libc::close(self.go);
        }
    }
}

pub(super) fn is_seccomp_stop(status: libc::c_int) -> bool {
    libc::WIFSTOPPED(status) && (status >> 16) & 0xff == sys::PTRACE_EVENT_SECCOMP
}

pub(super) fn gaps_of(events: &[TracerEvent]) -> Vec<(GapReason, OpSet, Option<u64>)> {
    events
        .iter()
        .filter_map(|event| match event {
            TracerEvent::Gap {
                reason, ops, count, ..
            } => Some((*reason, *ops, *count)),
            _ => None,
        })
        .collect()
}

pub(super) fn target_path(dir: &std::path::Path) -> (std::path::PathBuf, std::ffi::CString) {
    let target = dir.join("made");
    let c = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
    (target, c)
}
