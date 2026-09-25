#![cfg(target_os = "linux")]
#![allow(clippy::too_many_lines)]
//! J5 milestone proof: the lifetime clauses of jail-v1 §15 (L01, L02, L03,
//! L04, X07, C02) that J1 to J4 left without a test that can fail (slice
//! J5-B3, after the J5 acceptance-map review and the J5-B1 review).
//!
//! Every test drives the real `ouro-jail run` (or `gc`) on the reference host
//! and observes the tree itself, never only the receipt's word for it: the
//! target and its descendants are held by pidfds opened from the host pids
//! the attempt's own receipt names (or that `/proc` lists as the target's
//! children), and "dead" means the pidfd became readable. Waits are on
//! protocol events: control messages, pidfd readability, inotify, or state
//! polled under an explicit bound (`/proc`, cgroup files, a file the target
//! renames into place). Every process a test signals is one it started: the
//! supervisor it spawned, or a process of that attempt the attempt's receipt
//! or `/proc` names. A failing wait kills the attempt's own leaf and
//! supervisor and lets `gc` reconcile, so a failure leaves nothing in the
//! shared delegated subtree.
//!
//! The control channel is the test's own pipe at a fixed descriptor number
//! (and, where a test needs one, a gate at another), so a test can wait for
//! any control message kind while the run is still going.
//!
//! Live tests need `OURO_CONFORMANCE=1` on the reference host.

use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ouro_fixture::harness::gate::{Release, frame_bytes};
use ouro_fixture::harness::{self, Jail, LineReader, Run, Spawned};
use ouro_jail::platform::linux::{identity, watch};
use serde_json::Value;

mod common;

const PYTHON: &str = "/usr/bin/python3";

/// §9.3: 2 s cooperative grace, then a 5 s forced-stop verification budget.
/// A tree that is not dead within the sum plus scheduling slack was not ended
/// by the mechanism under test.
const STOP_BOUND: Duration = Duration::from_secs(10);

/// How soon after its deadline has passed on the boot clock the gate wait
/// must refuse: its 250 ms re-check (§8.2) plus the refusal's own work.
const GATE_RECHECK_BOUND: Duration = Duration::from_millis(700);

/// §9.3's forced-stop verification budget: a lifetime link's death ends the
/// tree within it (measured: tens of milliseconds).
const LINK_BOUND: Duration = Duration::from_secs(5);

// ===========================================================================
// Owner-side channels: control (and gate) at fixed descriptor numbers
// ===========================================================================

/// The descriptor number the jail writes control messages to. The harness
/// numbers its own channels upward from 3, so this never collides.
const CONTROL_FD: RawFd = 100;
/// The descriptor number the jail reads its gate from.
const GATE_FD: RawFd = 101;

/// Put `fd` at descriptor number `at` without close-on-exec, so the next
/// spawn inherits it. The returned descriptor is this process's copy, to be
/// dropped right after the spawn.
fn inheritable_at(fd: &OwnedFd, at: RawFd) -> OwnedFd {
    // SAFETY: F_GETFD only reads the flags of a descriptor number.
    assert_eq!(
        unsafe { libc::fcntl(at, libc::F_GETFD) },
        -1,
        "descriptor {at} is already in use in the test process"
    );
    // SAFETY: `fd` is a live descriptor this process owns and `at` is free;
    // `dup2` clears close-on-exec on the copy, which is the point.
    let placed = unsafe { libc::dup2(fd.as_raw_fd(), at) };
    assert_eq!(placed, at, "dup2: {}", std::io::Error::last_os_error());
    // SAFETY: `at` now names a descriptor this process owns and nothing else
    // refers to.
    unsafe { OwnedFd::from_raw_fd(at) }
}

/// A running attempt: the spawned supervisor with the owner's end of its
/// control channel (and gate, when it has one). Any wait that fails kills the
/// supervisor (this test's own child) and reports its exit and stderr.
struct Attempt {
    spawned: Option<Spawned>,
    reader: LineReader,
    seen: Vec<Value>,
    gate: Option<std::fs::File>,
}

impl Attempt {
    /// Spawn `jail` with the owner-side control channel (and a gate when
    /// asked).
    fn start(jail: Jail, gate: bool) -> Attempt {
        let (read, write) = harness::pipes::cloexec_pipe().expect("a control pipe");
        let control_copy = inheritable_at(&write, CONTROL_FD);
        drop(write);
        let mut jail = jail.args(["--control-fd", &CONTROL_FD.to_string()]);
        let mut gate_copy = None;
        let mut gate_writer = None;
        if gate {
            let (gate_read, gate_write) = harness::pipes::cloexec_pipe().expect("a gate pipe");
            gate_copy = Some(inheritable_at(&gate_read, GATE_FD));
            drop(gate_read);
            gate_writer = Some(std::fs::File::from(gate_write));
            jail = jail.args(["--gate-fd", &GATE_FD.to_string()]);
        }
        let timeout = jail.timeout;
        let spawned = jail.spawn();
        // The jail holds its own copies now; ours would postpone end of file.
        drop(control_copy);
        drop(gate_copy);
        let spawned = spawned.expect("the jail starts");
        let mut reader = LineReader::new(read);
        reader.timeout = timeout;
        reader.set_deadline(Instant::now() + timeout);
        Attempt {
            spawned: Some(spawned),
            reader,
            seen: Vec::new(),
            gate: gate_writer,
        }
    }

    fn spawned(&self) -> &Spawned {
        self.spawned.as_ref().expect("the attempt is running")
    }

    /// The supervisor's pid.
    fn pid(&self) -> i32 {
        i32::try_from(self.spawned().pid()).expect("a pid")
    }

    /// The durable receipt the latest control message acknowledged, checked.
    fn receipt(&self) -> Value {
        common::checked_receipt(
            self.spawned()
                .receipt_value()
                .expect("the --receipt copy is durable"),
        )
    }

    /// Stop here and fail, leaving nothing of this attempt on the shared
    /// host: kill the attempt's execution leaf (named by its own receipt,
    /// so every process in it is this test's) and the supervisor (this
    /// test's own child), let `gc` reconcile the attempt's state, remove the
    /// leaf if it is still there, and report the jail's exit and stderr.
    fn fail(&mut self, why: &str) -> ! {
        let mut spawned = self.spawned.take().expect("the attempt is running");
        let leaf = spawned.receipt_value().and_then(|receipt| {
            details(&receipt)["execution_cgroup"]["path"]
                .as_str()
                .map(PathBuf::from)
        });
        if let Some(leaf) = &leaf {
            let _ = std::fs::write(leaf.join("cgroup.kill"), "1");
        }
        let _ = spawned.kill();
        let (code, signal, stderr) = match spawned.wait() {
            Ok(run) => {
                let _ = gc_output(&run);
                (run.code(), run.signal(), run.stderr_text())
            }
            Err(error) => (None, None, format!("(no run: {error})")),
        };
        if let Some(leaf) = &leaf {
            let deadline = Instant::now() + Duration::from_secs(5);
            while std::fs::read_to_string(leaf.join("cgroup.events"))
                .is_ok_and(|events| events.contains("populated 1"))
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = std::fs::remove_dir(leaf);
        }
        panic!(
            "{why}\ncontrol so far: {:?}\njail exit {code:?} signal {signal:?}; stderr:\n{stderr}",
            self.seen
        );
    }

    /// The next control message; `None` at end of file.
    fn next(&mut self) -> Option<Value> {
        let line = match self.reader.next_line() {
            Ok(line) => line?,
            Err(error) => self.fail(&format!("control channel: {error}")),
        };
        match serde_json::from_slice::<Value>(&line) {
            Ok(value) => {
                self.seen.push(value.clone());
                Some(value)
            }
            Err(error) => self.fail(&format!(
                "control message is not JSON: {error}: {}",
                String::from_utf8_lossy(&line)
            )),
        }
    }

    /// Wait for the first message of `kind`; any terminal message before it
    /// fails the test.
    fn await_kind(&mut self, kind: &str) -> Value {
        loop {
            let Some(message) = self.next() else {
                self.fail(&format!("control closed before `{kind}`"));
            };
            let got = message["kind"].as_str().unwrap_or_default().to_owned();
            if got == kind {
                return message;
            }
            if matches!(got.as_str(), "settled" | "unsettled" | "refused") {
                self.fail(&format!("`{got}` arrived before `{kind}`"));
            }
        }
    }

    /// Wait for the terminal message: `settled`, `unsettled` or `refused`.
    fn await_terminal(&mut self) -> Value {
        loop {
            let Some(message) = self.next() else {
                self.fail("control closed with no terminal message");
            };
            if matches!(
                message["kind"].as_str(),
                Some("settled" | "unsettled" | "refused")
            ) {
                return message;
            }
        }
    }

    /// Release the gate with a valid frame for this attempt and close it.
    fn release(&mut self, attempt: &str, digest: &str) {
        let mut gate = self.gate.take().expect("this run has a gate");
        gate.write_all(&frame_bytes(&Release::Valid, attempt, digest))
            .expect("the release frame is written");
    }

    /// Wait for the jail to exit; return the run and the whole control
    /// transcript, read to end of file and checked against its schema and
    /// ordering rules.
    fn finish(mut self) -> (Run, Vec<Value>) {
        drop(self.gate.take());
        let run = self
            .spawned
            .take()
            .expect("the attempt is running")
            .wait()
            .expect("the jail finishes");
        while self.next().is_some() {}
        if let Err(error) = common::check_control(&self.seen) {
            panic!(
                "the control transcript fails its contract: {error}\n{:?}",
                self.seen
            );
        }
        (run, self.seen)
    }
}

// ===========================================================================
// Runs
// ===========================================================================

/// `run --profile <profile> --workspace <ws> --receipt ... --trace-fd ...`,
/// with the explicit memory ceiling `build` requires.
fn case(profile: &str) -> (Jail, PathBuf) {
    let jail = Jail::new().expect("a private jail harness");
    let workspace = jail.root().join("workspace");
    private_dir(&workspace);
    let mut jail = jail
        .arg("run")
        .args(["--profile", profile])
        .arg("--workspace")
        .arg(&workspace)
        .receipt()
        .trace();
    if profile == "build" {
        jail = jail.args(["--limit", "mem=256MiB"]);
    }
    (jail, workspace)
}

fn private_dir(path: &Path) {
    std::fs::create_dir(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

fn details(receipt: &Value) -> &Value {
    &receipt["lifetime"]["native"]["details"]
}

fn pid_at(receipt: &Value, key: &str) -> i32 {
    i32::try_from(
        details(receipt)[key]
            .as_i64()
            .unwrap_or_else(|| panic!("no `{key}` in {:#}", details(receipt))),
    )
    .expect("a pid")
}

fn leaf_of(receipt: &Value) -> PathBuf {
    PathBuf::from(
        details(receipt)["execution_cgroup"]["path"]
            .as_str()
            .unwrap_or_else(|| panic!("no execution leaf: {:#}", details(receipt))),
    )
}

fn limit_row<'a>(receipt: &'a Value, key: &str) -> &'a Value {
    receipt["applied"]["limits"]
        .as_array()
        .and_then(|limits| limits.iter().find(|l| l["key"] == key))
        .unwrap_or_else(|| panic!("no `{key}` limit row: {receipt:#}"))
}

/// The receipt with the highest revision, every receipt of the run held to
/// its contract.
fn last_receipt(run: &Run) -> Value {
    let receipts = run.receipts();
    for receipt in &receipts {
        if let Err(error) = common::check_receipt(receipt) {
            panic!("a product receipt fails its contract: {error}\n{receipt:#}");
        }
    }
    receipts
        .into_iter()
        .max_by_key(|r| r["revision"].as_u64().unwrap_or(0))
        .unwrap_or_else(|| panic!("no receipt; stderr: {}", run.stderr_text()))
}

/// The final receipt of a run that ended normally: receipts and the whole
/// trace held to their contracts (the trace must be complete, §13.3).
fn final_receipt(run: &Run) -> Value {
    common::assert_run_records(run);
    last_receipt(run)
}

/// The wrapper notes of a finished run whose trace is complete.
fn notes(run: &Run) -> Vec<Value> {
    run.trace_events()
        .iter()
        .filter(|e| e["operation"] == "note")
        .map(|e| e["fields"].clone())
        .collect()
}

fn assert_verified(receipt: &Value, scope: &str) {
    assert_eq!(receipt["phase"], "settled", "{receipt:#}");
    assert_eq!(receipt["lifetime"]["tree_empty"], true, "{receipt:#}");
    assert_eq!(receipt["lifetime"]["integrity"], "verified", "{receipt:#}");
    assert_eq!(receipt["lifetime"]["verification_scope"], scope);
    assert!(receipt["lifetime"]["verified_at"].is_string());
}

// ===========================================================================
// Processes
// ===========================================================================

fn pidfd(pid: i32) -> OwnedFd {
    identity::pidfd_open(pid).unwrap_or_else(|e| panic!("pidfd_open({pid}): {e}"))
}

fn dead(fd: &OwnedFd) -> bool {
    watch::readable(fd.as_raw_fd())
}

/// Block until the process behind `fd` has died, up to `within`. Returns how
/// long that took, or `None` when it was still alive at the bound.
fn await_death(fd: &OwnedFd, within: Duration) -> Option<Duration> {
    let start = Instant::now();
    loop {
        let left = within.saturating_sub(start.elapsed());
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = i32::try_from(left.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: one live pollfd for the duration of the call.
        let ready = unsafe { libc::poll(&raw mut pfd, 1, millis) };
        if ready > 0 {
            return Some(start.elapsed());
        }
        if ready == 0 || start.elapsed() >= within {
            return None;
        }
    }
}

/// Block until the process behind `fd` has died, at most until `since +
/// bound`. Returns the time from `since` (the signal or kill that should end
/// it) to its death, or `None` when it was still alive at `since + bound`.
/// Every bound a test states is measured from the event, never chained.
fn await_death_by(fd: &OwnedFd, since: Instant, bound: Duration) -> Option<Duration> {
    let until = since + bound;
    await_death(fd, until.saturating_duration_since(Instant::now()))?;
    Some(since.elapsed())
}

fn kill_by_pidfd(fd: &OwnedFd, signal: libc::c_int) {
    identity::pidfd_send_signal(fd.as_raw_fd(), signal).expect("the signal is delivered");
}

/// A bounded wait on kernel state that has no event to wait on (`/proc`,
/// cgroup files, a file the target writes): re-read every 2 ms, fail at the
/// bound.
fn poll_until<T>(what: &str, within: Duration, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + within;
    loop {
        if let Some(found) = probe() {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {within:?} waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// The host pids of every child of `pid`, over all its threads.
fn children(pid: i32) -> Vec<i32> {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for task in tasks.flatten() {
        if let Ok(text) = std::fs::read_to_string(task.path().join("children")) {
            found.extend(
                text.split_whitespace()
                    .filter_map(|p| p.parse::<i32>().ok()),
            );
        }
    }
    found
}

/// A signal mask line of `/proc/<pid>/status` (`SigIgn`, `SigCgt`).
fn signal_mask(pid: i32, field: &str) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status
        .lines()
        .find(|line| line.starts_with(&format!("{field}:")))?;
    u64::from_str_radix(line.split_whitespace().nth(1)?, 16).ok()
}

fn bit(signal: libc::c_int) -> u64 {
    1u64 << (signal - 1)
}

/// The process state letter of `/proc/<pid>/stat` (`Z` for a zombie).
fn state(pid: i32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .next()?
        .chars()
        .next()
}

/// The child of `parent` that ignores SIGTERM, found once it has set that
/// disposition, with a pidfd opened on it and its identity rechecked after
/// the open (so the pidfd cannot name a recycled pid).
fn term_ignoring_child(parent: i32) -> (i32, OwnedFd) {
    let pid = poll_until(
        "the target's SIGTERM-ignoring descendant",
        Duration::from_secs(20),
        || {
            children(parent).into_iter().find(|child| {
                signal_mask(*child, "SigIgn").is_some_and(|mask| mask & bit(libc::SIGTERM) != 0)
            })
        },
    );
    let fd = pidfd(pid);
    assert!(
        children(parent).contains(&pid) && !dead(&fd),
        "the descendant {pid} changed under the pidfd"
    );
    (pid, fd)
}

/// The target: a process whose child ignores SIGTERM and waits forever.
/// SIGUSR1 makes the target (only the target) exit 0; its handler is in place
/// before the child exists, so a test that has seen the child may send it.
/// The child has set its disposition before the target goes on (a pipe byte
/// orders it). With `ignore` the target then ignores SIGTERM too; with `catch
/// <path>` it catches SIGTERM, creates `<path>` and goes on.
const TREE: &str = r#"
import os, signal, sys
signal.signal(signal.SIGUSR1, lambda *_: os._exit(0))
r, w = os.pipe()
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(w, b"1")
    while True:
        signal.pause()
os.read(r, 1)
if sys.argv[1] == "ignore":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
elif sys.argv[1] == "catch":
    def caught(*_):
        open(sys.argv[2], "w").close()
    signal.signal(signal.SIGTERM, caught)
while True:
    signal.pause()
"#;

fn tree(mode: &str) -> [&str; 4] {
    [PYTHON, "-c", TREE, mode]
}

/// A started tree: the launcher (the target's host pid) and its
/// SIGTERM-ignoring descendant, both held by pidfds.
struct Tree {
    launcher_pid: i32,
    launcher: OwnedFd,
    descendant_pid: i32,
    descendant: OwnedFd,
}

/// After `exec_confirmed`: open the target and find its descendant.
fn started_tree(receipt: &Value) -> Tree {
    let launcher_pid = pid_at(receipt, "launcher_pid");
    let launcher = pidfd(launcher_pid);
    let (descendant_pid, descendant) = term_ignoring_child(launcher_pid);
    assert_ne!(descendant_pid, launcher_pid);
    Tree {
        launcher_pid,
        launcher,
        descendant_pid,
        descendant,
    }
}

/// The supervisor the test is about to signal is the real `ouro-jail`
/// process it spawned, and it catches `signal` (so delivery reaches the
/// handler, not a default action or an inherited ignore).
fn assert_real_supervisor_catches(supervisor: i32, signal: libc::c_int) {
    let exe = std::fs::read_link(format!("/proc/{supervisor}/exe")).expect("the supervisor's exe");
    let jail = std::fs::canonicalize(harness::jail_path()).expect("the jail binary");
    assert_eq!(
        exe, jail,
        "pid {supervisor} is not the ouro-jail supervisor"
    );
    let caught = signal_mask(supervisor, "SigCgt").expect("SigCgt");
    let ignored = signal_mask(supervisor, "SigIgn").expect("SigIgn");
    assert!(
        caught & bit(signal) != 0 && ignored & bit(signal) == 0,
        "the supervisor does not catch signal {signal}: SigCgt {caught:x} SigIgn {ignored:x}"
    );
}

fn signal_name(signal: libc::c_int) -> &'static str {
    match signal {
        libc::SIGINT => "INT",
        libc::SIGTERM => "TERM",
        libc::SIGHUP => "HUP",
        _ => "other",
    }
}

/// `ouro-jail gc --json` over a run's private state, as it came out.
fn gc_output(run: &Run) -> std::io::Result<std::process::Output> {
    std::process::Command::new(harness::jail_path())
        .args(["gc", "--json"])
        .env("OURO_DATA_DIR", &run.data_dir)
        .env("OURO_CONFIG_DIR", run.data_dir.with_file_name("config"))
        .output()
}

/// `ouro-jail gc --json` over a run's private state, with its report.
fn gc(run: &Run) -> (std::process::Output, Value) {
    let output = gc_output(run).expect("gc runs");
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "gc printed no JSON report ({e}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, report)
}

/// Signal the supervisor: this test's own unreaped child.
fn signal_supervisor(attempt: &Attempt, signal: libc::c_int) {
    // SAFETY: kill with a pid this test spawned and has not reaped.
    assert_eq!(unsafe { libc::kill(attempt.pid(), signal) }, 0);
}

/// For a gated attempt: wait for `prepared` and return its durable receipt
/// (which already names the blocked launcher).
fn await_prepared(attempt: &mut Attempt) -> Value {
    attempt.await_kind("prepared");
    attempt.receipt()
}

/// Release a prepared attempt. Returns the instant taken just before the
/// release frame was written, which precedes the start of the execution wall
/// (§8.1 step 6), so `t0 + wall` is a strict lower bound for the wall's
/// expiry on the test's own clock.
fn release_prepared(attempt: &mut Attempt, prepared: &Value) -> Instant {
    let id = prepared["attempt_id"].as_str().expect("an attempt id");
    let digest = prepared["policy"]["digest"]
        .as_str()
        .expect("a policy digest");
    let t0 = Instant::now();
    attempt.release(id, digest);
    t0
}

/// [`await_prepared`] then [`release_prepared`].
fn release_now(attempt: &mut Attempt) -> Instant {
    let prepared = await_prepared(attempt);
    release_prepared(attempt, &prepared)
}

// ===========================================================================
// L01: operator signals to a contained supervisor (L01.3)
// ===========================================================================

/// L01.3: operator INT, TERM and HUP, each delivered to the real supervisor
/// of a running `tool`, `agent` and `build` attempt, end the whole tree —
/// the target and a descendant — at verified death, within §9.3's budgets
/// measured from the signal. Before signalling, the test checks that the pid
/// is the `ouro-jail` process and that it catches the signal.
#[test]
fn l01_operator_int_term_and_hup_each_end_a_contained_tree() {
    if !common::live() {
        return;
    }
    for profile in ["tool", "agent", "build"] {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let name = signal_name(signal);
            let (jail, _) = case(profile);
            let mut attempt = Attempt::start(jail.target(tree("plain")), false);
            attempt.await_kind("exec_confirmed");
            let tree = started_tree(&attempt.receipt());
            assert_real_supervisor_catches(attempt.pid(), signal);
            let sent = Instant::now();
            signal_supervisor(&attempt, signal);
            let Some(took) = await_death_by(&tree.launcher, sent, STOP_BOUND) else {
                attempt.fail(&format!(
                    "{profile} {name}: the target outlived {STOP_BOUND:?}"
                ));
            };
            if await_death_by(&tree.descendant, sent, STOP_BOUND).is_none() {
                attempt.fail(&format!(
                    "{profile} {name}: the descendant {} outlived the stop",
                    tree.descendant_pid
                ));
            }
            let terminal = attempt.await_terminal();
            let (run, _) = attempt.finish();
            assert_eq!(terminal["kind"], "settled", "{profile} {name}");
            let receipt = final_receipt(&run);
            assert_verified(&receipt, "attempt_tree");
            assert_eq!(
                receipt["outcome"]["cause"], "operator_signal",
                "{profile} {name}"
            );
            // The cooperative stop is SIGTERM to the target, whatever the
            // operator sent; this target does not ignore it.
            assert_eq!(receipt["outcome"]["kind"], "signaled", "{profile} {name}");
            assert_eq!(receipt["outcome"]["signal"], libc::SIGTERM);
            assert_eq!(run.code(), Some(128 + libc::SIGTERM), "{profile} {name}");
            eprintln!("L01.3 {profile} {name}: target dead {took:?} after the signal");
        }
    }
}

// ===========================================================================
// L01: a SIGTERM-ignoring descendant under an operator signal (L01.12) and
// wall expiry (L01.10) of a contained run
// ===========================================================================

/// L01.12: the target and its descendant both ignore SIGTERM, so the
/// cooperative stop ends nothing and only the forced stop can. Operator
/// SIGTERM to the supervisor of a `tool` run, observation on and off: both
/// die within §9.3's grace plus budget of the signal, the target of SIGKILL,
/// and the tree is verified.
#[test]
fn l01_a_sigterm_ignoring_descendant_of_a_contained_run_dies_when_the_operator_signals() {
    if !common::live() {
        return;
    }
    for observe in ["on", "off"] {
        let (jail, _) = case("tool");
        let mut attempt = Attempt::start(
            jail.args(["--observe", observe]).target(tree("ignore")),
            false,
        );
        attempt.await_kind("exec_confirmed");
        let tree = started_tree(&attempt.receipt());
        poll_until(
            "the target to ignore SIGTERM",
            Duration::from_secs(10),
            || {
                signal_mask(tree.launcher_pid, "SigIgn")
                    .is_some_and(|mask| mask & bit(libc::SIGTERM) != 0)
                    .then_some(())
            },
        );
        assert_real_supervisor_catches(attempt.pid(), libc::SIGTERM);
        let sent = Instant::now();
        signal_supervisor(&attempt, libc::SIGTERM);
        let Some(took) = await_death_by(&tree.descendant, sent, STOP_BOUND) else {
            attempt.fail(&format!(
                "observe {observe}: the SIGTERM-ignoring descendant {} outlived {STOP_BOUND:?}",
                tree.descendant_pid
            ));
        };
        if await_death_by(&tree.launcher, sent, STOP_BOUND).is_none() {
            attempt.fail(&format!("observe {observe}: the target outlived the stop"));
        }
        let terminal = attempt.await_terminal();
        let (run, _) = attempt.finish();
        assert_eq!(terminal["kind"], "settled");
        let receipt = final_receipt(&run);
        assert_verified(&receipt, "attempt_tree");
        assert_eq!(receipt["outcome"]["cause"], "operator_signal");
        if observe == "on" {
            // Only the forced stop could end a target that ignores SIGTERM.
            assert_eq!(receipt["outcome"]["kind"], "signaled", "{receipt:#}");
            assert_eq!(receipt["outcome"]["signal"], libc::SIGKILL);
        }
        eprintln!("L01.12 observe {observe}: descendant dead {took:?} after the signal");
    }
}

/// The §9.3 cooperative grace before the forced stop.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// L01.10 and L01.1: wall expiry of a gated `tool` run. The wall runs from
/// release, so the test takes its own instant just before writing the release
/// frame and holds the product to both bounds on it: nothing ends before the
/// wall (a target and descendant that ignore SIGTERM not before the wall plus
/// the 2 s grace, since only the forced stop can end them), and everything is
/// dead within the wall plus §9.3's budgets. The receipt settles verified with
/// cause wall_expiry and the wall's hit.
///
/// Legs: `ignore` (L01.10, observation on and off: a multi-process tree whose
/// target and descendant ignore SIGTERM); `plain` (a target that dies of the
/// cooperative stop, its SIGTERM-ignoring descendant with the pid namespace);
/// `single` (L01.1: one `sleep`, no descendant).
#[test]
fn l01_wall_expiry_ends_a_contained_tree_with_a_sigterm_ignoring_descendant() {
    if !common::live() {
        return;
    }
    let wall = Duration::from_secs(2);
    for (mode, observe) in [
        ("ignore", "on"),
        ("ignore", "off"),
        ("plain", "on"),
        ("single", "on"),
        ("single", "off"),
    ] {
        let (jail, _) = case("tool");
        let jail = jail.args(["--observe", observe, "--limit", "wall=2s"]);
        let jail = if mode == "single" {
            jail.target(["/bin/sleep", "300"])
        } else {
            jail.target(tree(mode))
        };
        let mut attempt = Attempt::start(jail, true);
        // The launcher, blocked until the release, is held before it: a wall
        // that fired early cannot end it unseen.
        let prepared = await_prepared(&mut attempt);
        let launcher = pidfd(pid_at(&prepared, "launcher_pid"));
        let t0 = release_prepared(&mut attempt, &prepared);
        attempt.await_kind("exec_confirmed");
        let receipt = attempt.receipt();
        let mut deaths = Vec::new();
        if mode != "single" {
            let tree = started_tree(&receipt);
            let Some(descendant) = await_death_by(&tree.descendant, t0, wall + STOP_BOUND) else {
                attempt.fail(&format!(
                    "{mode} observe {observe}: the SIGTERM-ignoring descendant {} outlived the wall",
                    tree.descendant_pid
                ));
            };
            deaths.push(descendant);
        }
        let Some(target) = await_death_by(&launcher, t0, wall + STOP_BOUND) else {
            attempt.fail(&format!(
                "{mode} observe {observe}: the target outlived the wall"
            ));
        };
        deaths.push(target);
        let terminal = attempt.await_terminal();
        let (run, _) = attempt.finish();
        let floor = if mode == "ignore" {
            wall + STOP_GRACE
        } else {
            wall
        };
        assert!(
            deaths.iter().all(|death| *death >= floor),
            "{mode} observe {observe}: the tree ended before its wall: deaths {deaths:?} after \
             release, floor {floor:?}"
        );
        assert_eq!(terminal["kind"], "settled");
        let receipt = final_receipt(&run);
        assert_verified(&receipt, "attempt_tree");
        assert_eq!(receipt["outcome"]["cause"], "wall_expiry");
        assert_eq!(limit_row(&receipt, "wall")["hit"], true);
        if observe == "on" {
            let signal = if mode == "ignore" {
                libc::SIGKILL
            } else {
                libc::SIGTERM
            };
            assert_eq!(receipt["outcome"]["kind"], "signaled", "{receipt:#}");
            assert_eq!(receipt["outcome"]["signal"], signal);
        }
        eprintln!("L01.10 {mode} observe {observe}: target dead {target:?} after release");
    }
}

// ===========================================================================
// L01: a SIGTERM-ignoring descendant dies at settlement (L01.6); X07: it is
// dead before settlement is announced
// ===========================================================================

/// L01.6 (and X07.2 for `none`): the target exits 0 and leaves a descendant
/// that ignores SIGTERM. When the terminal control message arrives, the
/// descendant is already dead, and the receipt settles verified with the
/// target's own exit. Under `tool` the pid namespace ends the descendant with
/// the target; under `none` only the supervisor's kill of the leaf can
/// (observation off: no observer to kill it on the way out either), so a
/// `wait_tree` that claimed the tree empty without verifying it, or a stop
/// that did not kill the leaf, leaves the descendant alive at `settled` and
/// fails this test.
#[test]
fn l01_a_sigterm_ignoring_descendant_is_dead_before_settlement_is_announced() {
    if !common::live() {
        return;
    }
    // `none` without observation first: there the supervisor's leaf kill is
    // the only mechanism, so a mutation of it fails the first `none` leg.
    for (profile, observe) in [
        ("tool", "on"),
        ("tool", "off"),
        ("none", "off"),
        ("none", "on"),
    ] {
        let (jail, _) = case(profile);
        let mut attempt = Attempt::start(
            jail.args(["--observe", observe]).target(tree("plain")),
            false,
        );
        attempt.await_kind("exec_confirmed");
        let tree = started_tree(&attempt.receipt());
        // The target exits 0 on its own; the descendant stays behind it.
        kill_by_pidfd(&tree.launcher, libc::SIGUSR1);
        if await_death(&tree.launcher, STOP_BOUND).is_none() {
            attempt.fail("the target did not exit on SIGUSR1");
        }
        let terminal = attempt.await_terminal();
        let alive_at_terminal = !dead(&tree.descendant);
        if alive_at_terminal {
            // Only after a failure: end what this test started.
            kill_by_pidfd(&tree.descendant, libc::SIGKILL);
        }
        let (run, _) = attempt.finish();
        assert!(
            !alive_at_terminal,
            "{profile} observe {observe}: the descendant {} was alive when `{}` was announced",
            tree.descendant_pid, terminal["kind"]
        );
        assert_eq!(terminal["kind"], "settled", "{profile} observe {observe}");
        let receipt = final_receipt(&run);
        let scope = if profile == "none" {
            "registered_boundary"
        } else {
            "attempt_tree"
        };
        assert_verified(&receipt, scope);
        assert_eq!(receipt["outcome"]["kind"], "exited", "{receipt:#}");
        assert_eq!(receipt["outcome"]["code"], 0);
        assert_eq!(run.code(), Some(0));
    }
}

// ===========================================================================
// X07.2: a tree whose emptiness cannot be verified is never claimed empty
// ===========================================================================

/// A process of the test's own, moved into the execution leaf and traced by
/// the test with `PTRACE_O_TRACEEXIT`. Killed, it stops at its exit
/// (`PTRACE_EVENT_EXIT`, measured on the reference kernel 7.0 for a
/// SIGKILLed tracee) before it leaves its cgroup, so the leaf stays populated
/// for as long as the test holds it: a member that the supervisor's kill
/// reaches and that still cannot be verified dead.
struct HeldMember {
    pid: libc::pid_t,
    released: bool,
}

impl HeldMember {
    /// Start `sleep`, move it into `leaf`, and trace it. Must be called on
    /// the thread that later calls [`HeldMember::release`] (ptrace requests
    /// come from the tracing thread).
    fn plant(leaf: &Path) -> HeldMember {
        let child = std::process::Command::new("/bin/sleep")
            .arg("120")
            .spawn()
            .expect("a sleep of the test's own");
        let pid = libc::pid_t::try_from(child.id()).expect("a pid");
        // The handle is not needed: the test reaps this pid itself below.
        drop(child);
        let held = HeldMember {
            pid,
            released: false,
        };
        std::fs::write(leaf.join("cgroup.procs"), pid.to_string())
            .expect("the test's process moves into the leaf");
        // SAFETY: PTRACE_SEIZE of this test's own child; no pointers.
        let seized = unsafe {
            libc::ptrace(
                libc::PTRACE_SEIZE,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                libc::PTRACE_O_TRACEEXIT as usize as *mut libc::c_void,
            )
        };
        assert_eq!(seized, 0, "seize: {}", std::io::Error::last_os_error());
        held
    }

    /// Whether something killed it: it is waiting at its exit stop.
    fn killed(&self) -> bool {
        let mut status = 0;
        // SAFETY: waitpid on this test's own traced child, without blocking.
        let got = unsafe { libc::waitpid(self.pid, &raw mut status, libc::WNOHANG | libc::__WALL) };
        got == self.pid && libc::WIFSTOPPED(status) && (status >> 16) == libc::PTRACE_EVENT_EXIT
    }

    /// Let it finish dying (killing it first if nothing did) and reap it.
    fn release(&mut self, already_stopped: bool) {
        if self.released {
            return;
        }
        self.released = true;
        let mut status = 0;
        if !already_stopped {
            // SAFETY: SIGKILL to this test's own child.
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
            // SAFETY: waitpid on this test's own traced child.
            unsafe { libc::waitpid(self.pid, &raw mut status, libc::__WALL) };
        }
        // SAFETY: PTRACE_DETACH of this test's own stopped tracee.
        unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                self.pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            );
        }
        // SAFETY: reaping this test's own child.
        unsafe { libc::waitpid(self.pid, &raw mut status, libc::__WALL) };
    }
}

impl Drop for HeldMember {
    /// A test that fails before releasing still lets the member go.
    fn drop(&mut self) {
        let stopped = self.killed();
        self.release(stopped);
    }
}

/// X07.2: a claim of tree emptiness is made only when it was verified. The
/// target exits with a descendant behind it, but the execution leaf holds one
/// more member: a process of the test's own that the supervisor's kill
/// reaches and that cannot finish dying while the test holds it at its exit
/// stop (a stand-in for a member that cannot be verified dead within §9.3's
/// 5-second budget). The run must end `unsettled`: no settled receipt,
/// `tree_empty` null, `tree_unknown`, exit 1, and the member must have been
/// killed by the supervisor. A `wait_tree` that claimed the tree empty without
/// seeing the leaf unpopulated (at once, after its kill, or from the pid
/// namespace alone) settles and fails this test. Released, the member dies;
/// `gc` then verifies and removes the retained leaf.
///
/// `tool` (the pid namespace ends the descendant) and `none` with observation
/// off and on (the supervisor's leaf kill ends it; the registered boundary is
/// the leaf).
#[test]
fn x07_a_leaf_that_cannot_be_verified_empty_is_never_claimed_empty() {
    if !common::live() {
        return;
    }
    for (profile, observe) in [("tool", "on"), ("none", "off"), ("none", "on")] {
        let (jail, _) = case(profile);
        let mut attempt = Attempt::start(
            jail.args(["--observe", observe]).target(tree("plain")),
            false,
        );
        attempt.await_kind("exec_confirmed");
        let receipt = attempt.receipt();
        let tree = started_tree(&receipt);
        let leaf = leaf_of(&receipt);
        let mut member = HeldMember::plant(&leaf);
        kill_by_pidfd(&tree.launcher, libc::SIGUSR1);
        let terminal = attempt.await_terminal();
        let killed = member.killed();
        member.release(killed);
        let (run, _) = attempt.finish();
        // Whatever happened, nothing is in the leaf now; gc verifies and
        // removes the retained leaf before anything is asserted, so a failure
        // leaves nothing of this test in the shared delegated subtree.
        poll_until("the leaf to empty", Duration::from_secs(10), || {
            std::fs::read_to_string(leaf.join("cgroup.events")).map_or(Some(()), |events| {
                events.contains("populated 0").then_some(())
            })
        });
        let (output, report) = gc(&run);
        let leg = format!("{profile} observe {observe}");
        assert!(
            dead(&tree.descendant),
            "{leg}: the target's descendant survived"
        );
        assert_eq!(
            terminal["kind"], "unsettled",
            "{leg}: a leaf that was never seen empty was announced: {terminal}"
        );
        assert!(
            killed,
            "{leg}: the supervisor never killed the leaf's extra member, so nothing was proved"
        );
        let receipt = final_receipt(&run);
        assert_ne!(receipt["phase"], "settled", "{leg}: {receipt:#}");
        assert!(
            receipt["lifetime"]["tree_empty"].is_null(),
            "{leg}: {receipt:#}"
        );
        assert!(receipt["lifetime"]["verified_at"].is_null());
        assert!(
            receipt["errors"]
                .as_array()
                .is_some_and(|errors| errors.iter().any(|e| e["code"] == "tree_unknown")),
            "{leg}: {receipt:#}"
        );
        assert_eq!(run.code(), Some(1), "{leg}: {}", run.stderr_text());
        assert!(output.status.success(), "{leg}: {report:#}");
        assert!(!leaf.exists(), "{leg}: gc left the leaf: {report:#}");
    }
}

// ===========================================================================
// L01: a fork burst is fully reaped (L01.7)
// ===========================================================================

/// The target: fork `n` children that each exec `/bin/true`, reap every one,
/// and exit 0 only when all `n` were forked and exited 0.
const BURST: &str = r#"
import os, sys
n = int(sys.argv[1])
pids = []
for _ in range(n):
    pid = os.fork()
    if pid == 0:
        os.execv("/bin/true", ["/bin/true"])
    pids.append(pid)
ok = sum(1 for pid in pids if os.waitpid(pid, 0)[1] == 0)
print(f"burst forked={len(pids)} reaped_ok={ok}", flush=True)
sys.exit(0 if ok == n else 1)
"#;

/// The target: fork `n` children that exit at once, wait until every one is
/// a zombie (reaped by nobody), and exit 0, orphaning all `n` zombies.
const ORPHANS: &str = r#"
import os, sys, time
n = int(sys.argv[1])
pids = []
for _ in range(n):
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
print(f"orphans={len(pids)}", flush=True)
os._exit(0)
"#;

const BURST_SIZE: usize = 120;

/// While it lives, this test process adopts orphans (it is a child
/// subreaper), so whatever a supervisor leaves behind when it exits comes back
/// here to be counted. Children the test already had are not counted.
struct Subreaper {
    before: Vec<i32>,
}

impl Subreaper {
    fn start() -> Subreaper {
        // SAFETY: prctl with integer arguments only.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        Subreaper {
            before: Subreaper::children(),
        }
    }

    fn children() -> Vec<i32> {
        // SAFETY: getpid takes no arguments and cannot fail.
        children(unsafe { libc::getpid() })
    }

    /// Every child of this process that it did not have at the start, with
    /// its state letter.
    fn adopted(&self) -> Vec<(i32, Option<char>)> {
        Subreaper::children()
            .into_iter()
            .filter(|pid| !self.before.contains(pid))
            .map(|pid| (pid, state(pid)))
            .collect()
    }
}

impl Drop for Subreaper {
    fn drop(&mut self) {
        // Reap whatever was handed over, then stop adopting.
        for (pid, _) in self.adopted() {
            let mut status = 0;
            // SAFETY: `pid` is this process's own child.
            unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        }
        // SAFETY: prctl with integer arguments only.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) };
    }
}

/// L01.7: a fork burst is fully reaped.
///
/// `tool`: the target forks 120 children that exec `/bin/true` and reaps
/// them; it exits 0 only if all 120 were forked and exited 0, the observer
/// witnessed each child's end (a `proc.exit` for every one), and the tree is
/// verified.
///
/// `none`: the target forks 120 children, waits until every one is an
/// unreaped zombie and exits, orphaning them to the supervisor (a child
/// subreaper, §9.3). The supervisor must reap them all: when it exits, this
/// test (itself a subreaper for the duration) adopts whatever it left, and
/// nothing may be left.
#[test]
fn l01_a_fork_burst_is_fully_reaped() {
    if !common::live() {
        return;
    }
    let (jail, _) = case("tool");
    let attempt = Attempt::start(
        jail.target([PYTHON, "-c", BURST, &BURST_SIZE.to_string()]),
        false,
    );
    let (run, _) = attempt.finish();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    assert!(
        run.stdout_text()
            .contains(&format!("burst forked={BURST_SIZE} reaped_ok={BURST_SIZE}")),
        "{}",
        run.stdout_text()
    );
    let receipt = final_receipt(&run);
    assert_verified(&receipt, "attempt_tree");
    assert_eq!(receipt["outcome"]["kind"], "exited");
    let clean_exits = run
        .trace_events()
        .iter()
        .filter(|e| {
            e["operation"] == "proc.exit"
                && e["fields"]["termination"] == "exited"
                && e["fields"]["exit_code"] == 0
        })
        .count();
    // Every child, and the target itself.
    assert!(
        clean_exits > BURST_SIZE,
        "the observer witnessed {clean_exits} clean exits for {BURST_SIZE} children and the target"
    );

    for observe in ["on", "off"] {
        let subreaper = Subreaper::start();
        let (jail, _) = case("none");
        let attempt = Attempt::start(
            jail.args(["--observe", observe]).target([
                PYTHON,
                "-c",
                ORPHANS,
                &BURST_SIZE.to_string(),
            ]),
            false,
        );
        let (run, _) = attempt.finish();
        let left = subreaper.adopted();
        drop(subreaper);
        assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
        assert!(
            run.stdout_text().contains(&format!("orphans={BURST_SIZE}")),
            "{}",
            run.stdout_text()
        );
        let receipt = final_receipt(&run);
        assert_verified(&receipt, "registered_boundary");
        assert!(
            left.is_empty(),
            "observe {observe}: the supervisor exited leaving {} process(es) unreaped: {left:?}",
            left.len()
        );
    }
}

// ===========================================================================
// L01: a fork storm stopped mid-flight (L01.8)
// ===========================================================================

/// The target: fork without end, every process ignoring SIGTERM, retrying
/// when the pids ceiling refuses a fork.
const STORM: &str = r#"
import os, signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    try:
        pid = os.fork()
    except OSError:
        time.sleep(0.002)
        continue
    if pid == 0:
        while True:
            signal.pause()
"#;

fn pids_events_max(leaf: &Path) -> Option<u64> {
    std::fs::read_to_string(leaf.join("pids.events"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("max ")?.trim().parse().ok())
}

/// L01.8: a fork storm under `tool` with a 64-pid ceiling is proved to be
/// running when it is stopped — the leaf holds at least 60 processes and the
/// kernel's count of forks the ceiling refused is still rising — and operator
/// SIGTERM then ends it (every process ignores SIGTERM, so only the forced
/// stop can) at verified tree death: the namespace init and the leaf are
/// gone within §9.3's budgets of the signal.
#[test]
fn l01_a_fork_storm_stopped_mid_flight_ends_at_verified_tree_death() {
    if !common::live() {
        return;
    }
    let (jail, _) = case("tool");
    let mut attempt = Attempt::start(
        jail.args(["--limit", "pids=64"])
            .target([PYTHON, "-c", STORM]),
        false,
    );
    attempt.await_kind("exec_confirmed");
    let receipt = attempt.receipt();
    let init = pidfd(pid_at(&receipt, "namespace_init_pid"));
    let launcher = pidfd(pid_at(&receipt, "launcher_pid"));
    let leaf = leaf_of(&receipt);
    poll_until(
        "the storm to fill its ceiling",
        Duration::from_secs(30),
        || {
            std::fs::read_to_string(leaf.join("pids.current"))
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|current| *current >= 60)
        },
    );
    let first = poll_until("a refused fork", Duration::from_secs(10), || {
        pids_events_max(&leaf).filter(|count| *count > 0)
    });
    let second = poll_until("the storm to keep forking", Duration::from_secs(10), || {
        pids_events_max(&leaf).filter(|count| *count > first)
    });
    assert_real_supervisor_catches(attempt.pid(), libc::SIGTERM);
    let sent = Instant::now();
    signal_supervisor(&attempt, libc::SIGTERM);
    let Some(took) = await_death_by(&init, sent, STOP_BOUND) else {
        attempt.fail(&format!("the storm's namespace outlived {STOP_BOUND:?}"));
    };
    if await_death_by(&launcher, sent, STOP_BOUND).is_none() {
        attempt.fail("the storm's target outlived the stop");
    }
    let terminal = attempt.await_terminal();
    let (run, _) = attempt.finish();
    assert_eq!(terminal["kind"], "settled");
    let receipt = final_receipt(&run);
    assert_verified(&receipt, "attempt_tree");
    assert_eq!(receipt["outcome"]["cause"], "operator_signal");
    assert_eq!(limit_row(&receipt, "pids")["hit"], true);
    assert!(!leaf.exists(), "the leaf outlived settlement");
    eprintln!(
        "L01.8: {first} then {second} refused forks before the stop; init dead {took:?} after it"
    );
}

// ===========================================================================
// L01: operator signals to a `none` supervisor (L01.4, L01.11)
// ===========================================================================

/// L01.4 and L01.11: operator INT, TERM and HUP to the supervisor of a `none`
/// run whose leaf is intact end the tree at verified death: the target dies
/// of the cooperative stop, its SIGTERM-ignoring descendant of the kill of
/// the leaf, both within §9.3's budgets of the signal and before `settled`
/// is announced, observation on and off.
#[test]
fn l01_operator_int_term_and_hup_each_end_a_none_tree_at_verified_death() {
    if !common::live() {
        return;
    }
    for observe in ["off", "on"] {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let name = signal_name(signal);
            let (jail, _) = case("none");
            let mut attempt = Attempt::start(
                jail.args(["--observe", observe]).target(tree("plain")),
                false,
            );
            attempt.await_kind("exec_confirmed");
            let tree = started_tree(&attempt.receipt());
            assert_real_supervisor_catches(attempt.pid(), signal);
            let sent = Instant::now();
            signal_supervisor(&attempt, signal);
            if await_death_by(&tree.launcher, sent, STOP_BOUND).is_none() {
                attempt.fail(&format!(
                    "{name} observe {observe}: the target outlived the stop"
                ));
            }
            let terminal = attempt.await_terminal();
            let alive = !dead(&tree.descendant);
            if alive {
                kill_by_pidfd(&tree.descendant, libc::SIGKILL);
            }
            let (run, _) = attempt.finish();
            assert!(
                !alive,
                "{name} observe {observe}: the descendant {} was alive at `{}`",
                tree.descendant_pid, terminal["kind"]
            );
            assert_eq!(terminal["kind"], "settled", "{name} observe {observe}");
            let receipt = final_receipt(&run);
            assert_verified(&receipt, "registered_boundary");
            assert_eq!(receipt["outcome"]["cause"], "operator_signal");
        }
    }
}

// ===========================================================================
// L02: helper and supervisor kills
// ===========================================================================

/// L02.9: killing the backend (bubblewrap's outer process) of a real `tool`
/// run kills the target and its descendant within §9.3's budget of the kill,
/// and the receipt records how without inventing an exit: with observation
/// the target was SIGKILLed (`signaled`, 9, exit 137, no stop cause: the
/// kernel's parent-death chain acted, not the supervisor); without it the
/// backend reported no code for the target (`unknown`, exit 1). The tree is
/// verified either way.
#[test]
fn l02_killing_the_backend_of_a_real_run_ends_the_tree_and_the_receipt_says_how() {
    if !common::live() {
        return;
    }
    for observe in ["on", "off"] {
        let (jail, _) = case("tool");
        let mut attempt = Attempt::start(
            jail.args(["--observe", observe]).target(tree("plain")),
            false,
        );
        attempt.await_kind("exec_confirmed");
        let receipt = attempt.receipt();
        let tree = started_tree(&receipt);
        let backend = pidfd(pid_at(&receipt, "bwrap_pid"));
        let killed_at = Instant::now();
        kill_by_pidfd(&backend, libc::SIGKILL);
        let Some(took) = await_death_by(&tree.launcher, killed_at, LINK_BOUND) else {
            attempt.fail(&format!(
                "observe {observe}: the target outlived the backend by {LINK_BOUND:?}"
            ));
        };
        if await_death_by(&tree.descendant, killed_at, LINK_BOUND).is_none() {
            attempt.fail(&format!(
                "observe {observe}: the descendant outlived the backend"
            ));
        }
        let terminal = attempt.await_terminal();
        let (run, _) = attempt.finish();
        assert_eq!(terminal["kind"], "settled");
        let receipt = final_receipt(&run);
        assert_verified(&receipt, "attempt_tree");
        let outcome = &receipt["outcome"];
        assert_ne!(outcome["kind"], "exited", "{outcome:#}");
        assert!(outcome["code"].is_null(), "{outcome:#}");
        if observe == "on" {
            assert_eq!(outcome["kind"], "signaled", "{outcome:#}");
            assert_eq!(outcome["signal"], libc::SIGKILL);
            assert!(outcome["cause"].is_null(), "{outcome:#}");
            assert_eq!(run.code(), Some(128 + libc::SIGKILL));
        } else {
            assert_eq!(outcome["kind"], "unknown", "{outcome:#}");
            assert!(outcome["signal"].is_null());
            assert_eq!(run.code(), Some(1));
        }
        eprintln!("L02.9 observe {observe}: target dead {took:?} after the backend kill");
    }
}

/// L02.4: under `agent` and `build`, SIGKILL of the lifetime link `link`
/// (`bwrap_pid`, `watcher_pid` or `supervisor`) ends the target, its
/// descendant, every charged helper and the watcher within §9.3's budget of
/// the kill. Backend and watcher: the supervisor settles verified.
/// Supervisor: nothing is left to write, the last receipt claims no outcome,
/// and `gc` finds the owner dead and removes the leaf.
fn l02_kill_link(link: &str) {
    for profile in ["agent", "build"] {
        let (jail, _) = case(profile);
        let mut attempt = Attempt::start(jail.target(tree("plain")), false);
        attempt.await_kind("exec_confirmed");
        let receipt = attempt.receipt();
        let tree = started_tree(&receipt);
        let mut held: Vec<(String, OwnedFd)> =
            details(&receipt)["execution_cgroup"]["charged_helpers"]
                .as_array()
                .expect("charged helpers")
                .iter()
                .map(|h| {
                    let pid = h["pid"].as_i64().expect("a pid");
                    (
                        h["role"].as_str().unwrap_or_default().to_owned(),
                        pidfd(i32::try_from(pid).expect("a pid")),
                    )
                })
                .collect();
        if profile == "agent" {
            assert!(held.iter().any(|(role, _)| role == "bridge"));
        }
        held.push(("watcher".to_owned(), pidfd(pid_at(&receipt, "watcher_pid"))));
        let killed = if link == "supervisor" {
            pidfd(attempt.pid())
        } else {
            pidfd(pid_at(&receipt, link))
        };
        let killed_at = Instant::now();
        kill_by_pidfd(&killed, libc::SIGKILL);
        let Some(took) = await_death_by(&tree.launcher, killed_at, LINK_BOUND) else {
            attempt.fail(&format!(
                "{profile} {link}: the target outlived the kill by {LINK_BOUND:?}"
            ));
        };
        if await_death_by(&tree.descendant, killed_at, LINK_BOUND).is_none() {
            attempt.fail(&format!(
                "{profile} {link}: the descendant outlived the kill"
            ));
        }
        for (role, fd) in &held {
            if await_death_by(fd, killed_at, LINK_BOUND).is_none() {
                attempt.fail(&format!("{profile} {link}: the {role} outlived the kill"));
            }
        }
        if link == "supervisor" {
            let (run, _) = attempt.finish();
            assert_eq!(run.signal(), Some(libc::SIGKILL));
            // The trace ends where the supervisor died; only the receipts
            // are complete records.
            let last = last_receipt(&run);
            assert_ne!(last["phase"], "settled");
            assert_eq!(last["outcome"]["kind"], "pending", "{last:#}");
            let (output, report) = gc(&run);
            assert!(output.status.success(), "{report:#}");
            let leaf = leaf_of(&receipt);
            assert!(!leaf.exists(), "gc left the leaf: {report:#}");
        } else {
            let terminal = attempt.await_terminal();
            let (run, _) = attempt.finish();
            assert_eq!(terminal["kind"], "settled", "{profile} {link}");
            let receipt = final_receipt(&run);
            assert_verified(&receipt, "attempt_tree");
            assert_eq!(receipt["outcome"]["kind"], "signaled", "{receipt:#}");
            assert_eq!(receipt["outcome"]["signal"], libc::SIGKILL);
        }
        eprintln!("L02.4 {profile} {link}: target dead {took:?} after the kill");
    }
}

/// L02.4, the backend (bubblewrap's outer process) of `agent` and `build`.
#[test]
fn l02_killing_the_backend_of_agent_or_build_ends_the_tree_within_a_bound() {
    if common::live() {
        l02_kill_link("bwrap_pid");
    }
}

/// L02.4, the lifetime watcher of `agent` and `build` (§9.3: "watcher death
/// makes the supervisor stop the boundary").
#[test]
fn l02_killing_the_watcher_of_agent_or_build_ends_the_tree_within_a_bound() {
    if common::live() {
        l02_kill_link("watcher_pid");
    }
}

/// L02.4, the supervisor of `agent` and `build` (§9.3: "supervisor death
/// makes the watcher kill the whole leaf and then bubblewrap").
#[test]
fn l02_killing_the_supervisor_of_agent_or_build_ends_the_tree_within_a_bound() {
    if common::live() {
        l02_kill_link("supervisor");
    }
}

/// How long the bridge test watches the target after the bridge's death.
const BRIDGE_GRACE_WATCH: Duration = Duration::from_secs(1);

/// The target of the bridge test: connect to the bridge once, report, wait
/// for SIGUSR1, connect again, report, exit 0.
const BRIDGE_CLIENT: &str = r#"
import os, signal, socket, sys
out = sys.argv[1]
def attempt():
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect(("127.0.0.1", 3128))
        return "connected"
    except OSError as e:
        return "failed:%s" % e.errno
    finally:
        s.close()
def report(name, text):
    with open(out + "/" + name + ".tmp", "w") as f:
        f.write(text)
    os.rename(out + "/" + name + ".tmp", out + "/" + name)
go = []
signal.signal(signal.SIGUSR1, lambda *_: go.append(1))
report("before", attempt())
while not go:
    signal.pause()
report("after", attempt())
"#;

/// L02.4, the bridge (§10): `agent`'s loopback bridge is not a lifetime
/// link. Its death "loses no evidence: it is recorded once, when it happens
/// before settlement, and new connections fail" (fail closed). The test
/// connects through the bridge, kills it, and then the target — still alive,
/// the tree continues — finds new connections refused and exits 0 on its
/// own; the trace holds exactly one `bridge_exited` helper note, the receipt
/// no error, and the tree settles verified.
#[test]
fn l02_the_agent_bridges_death_is_noted_once_fails_closed_and_the_tree_continues() {
    if !common::live() {
        return;
    }
    let (jail, workspace) = case("agent");
    let mut attempt = Attempt::start(
        jail.target([
            PYTHON,
            "-c",
            BRIDGE_CLIENT,
            workspace.to_str().expect("UTF-8"),
        ]),
        false,
    );
    attempt.await_kind("exec_confirmed");
    let receipt = attempt.receipt();
    let launcher = pidfd(pid_at(&receipt, "launcher_pid"));
    let bridge_pid = details(&receipt)["execution_cgroup"]["charged_helpers"]
        .as_array()
        .and_then(|helpers| helpers.iter().find(|h| h["role"] == "bridge"))
        .and_then(|h| h["pid"].as_i64())
        .expect("the bridge is a charged helper");
    let bridge = pidfd(i32::try_from(bridge_pid).expect("a pid"));
    let before = poll_until("the first connect", Duration::from_secs(20), || {
        std::fs::read_to_string(workspace.join("before")).ok()
    });
    kill_by_pidfd(&bridge, libc::SIGKILL);
    if await_death(&bridge, LINK_BOUND).is_none() {
        attempt.fail("the bridge outlived SIGKILL");
    }
    // The tree continues: the target is still alive a full second after the
    // bridge's death, far longer than the supervisor takes to notice it (its
    // note is in the trace) and act on anything it acted on.
    if await_death(&launcher, BRIDGE_GRACE_WATCH).is_some() {
        attempt.fail("the bridge's death ended the target: the tree did not continue");
    }
    kill_by_pidfd(&launcher, libc::SIGUSR1);
    if await_death(&launcher, STOP_BOUND).is_none() {
        attempt.fail("the target did not finish after SIGUSR1");
    }
    let terminal = attempt.await_terminal();
    let (run, _) = attempt.finish();
    assert_eq!(
        before, "connected",
        "the bridge did not accept before its death"
    );
    let after = std::fs::read_to_string(workspace.join("after")).expect("the second connect");
    assert_eq!(
        after,
        format!("failed:{}", libc::ECONNREFUSED),
        "a connect after the bridge's death did not fail closed"
    );
    assert_eq!(terminal["kind"], "settled");
    let receipt = final_receipt(&run);
    assert_verified(&receipt, "attempt_tree");
    assert_eq!(receipt["outcome"]["kind"], "exited", "{receipt:#}");
    assert_eq!(receipt["outcome"]["code"], 0);
    assert!(
        receipt["outcome"]["cause"].is_null(),
        "the bridge's death stopped the attempt: {receipt:#}"
    );
    assert!(
        receipt["errors"].as_array().is_some_and(Vec::is_empty),
        "the bridge's death lost evidence: {receipt:#}"
    );
    assert_eq!(
        receipt["observer"]["sources"]["proxy"], "active",
        "the bridge's death degraded the proxy's evidence: {receipt:#}"
    );
    let bridge_notes: Vec<Value> = notes(&run)
        .into_iter()
        .filter(|fields| fields["kind"] == "helper" && fields["helper"] == "bridge")
        .collect();
    assert_eq!(bridge_notes.len(), 1, "{bridge_notes:?}");
    assert_eq!(bridge_notes[0]["transition"], "bridge_exited");
    assert_eq!(run.code(), Some(0));
}

// ===========================================================================
// L03: a required limit whose leaf cannot be created (L03.7), and the
// preferred ceiling recorded absent (L03.6's limited behaviour)
// ===========================================================================

/// A fresh attempt id in the grammar of §7 (`att_` and a UUID v4).
fn attempt_id() -> String {
    let mut bytes = [0u8; 16];
    // SAFETY: a live 16-byte buffer; getrandom writes at most that.
    let got = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    assert_eq!(got, 16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "att_{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The name the attempt's execution leaf will have (§14.2), taken first by
/// the test inside the delegated subtree, so the supervisor's exclusive
/// `mkdir` of it fails. Removed when dropped (nothing is ever placed in it).
struct TakenLeaf(PathBuf);

impl TakenLeaf {
    fn take(attempt: &str) -> TakenLeaf {
        // SAFETY: getuid takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        let root = ouro_jail::platform::linux::cgroup::delegated_root(uid)
            .expect("the reference host delegates a cgroup subtree");
        let path = root.join(format!("ouro-{attempt}.leaf"));
        std::fs::create_dir(&path).expect("the leaf name is free and the subtree writable");
        TakenLeaf(path)
    }

    fn identity(&self) -> Option<(u64, u64)> {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(&self.0)
            .ok()
            .map(|meta| (meta.dev(), meta.ino()))
    }
}

impl Drop for TakenLeaf {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

/// L03.7: a contained profile whose required limit needs a cgroup that cannot
/// be created refuses before exec. The owner binds the attempt id
/// (`--attempt-id` with `--gate-fd`), so the test can take the leaf's name
/// first; the supervisor's exclusive `mkdir` then fails and, with an explicit
/// (required) pids or memory ceiling, the run refuses with exit 125,
/// `missing_capability`, no `prepared` and no exec. Checked for `tool` and
/// `agent` with pids, and `build` with its required memory ceiling. The taken
/// directory is never adopted or removed by the jail.
#[test]
fn l03_a_required_limit_whose_leaf_cannot_be_created_refuses_before_exec() {
    if !common::live() {
        return;
    }
    // `build`'s required memory ceiling is the one `case` always supplies.
    for (profile, limit) in [
        ("tool", Some("pids=64")),
        ("agent", Some("pids=64")),
        ("build", None),
    ] {
        let id = attempt_id();
        let taken = TakenLeaf::take(&id);
        let identity = taken.identity();
        let (jail, workspace) = case(profile);
        let marker = workspace.join("target-ran");
        let mut jail = jail.args(["--attempt-id", &id]);
        if let Some(limit) = limit {
            jail = jail.args(["--limit", limit]);
        }
        let jail = jail.target(["/bin/sh", "-c", &format!(": > {}", marker.display())]);
        let mut attempt = Attempt::start(jail, true);
        // The gate stays closed: a run that got as far as `prepared` would
        // wait for it, so the first message is the verdict.
        let Some(first) = attempt.next() else {
            attempt.fail(&format!("{profile}: no control message at all"));
        };
        if first["kind"] != "refused" {
            attempt.fail(&format!(
                "{profile}: the attempt went on without the leaf its required limit needs: {first}"
            ));
        }
        let (run, transcript) = attempt.finish();
        assert!(
            transcript
                .iter()
                .all(|m| m["kind"] != "prepared" && m["kind"] != "exec_confirmed"),
            "{profile}: {transcript:?}"
        );
        assert_eq!(run.code(), Some(125), "{profile}: {}", run.stderr_text());
        assert!(!marker.exists(), "{profile}: the target ran");
        let receipt = final_receipt(&run);
        assert_eq!(receipt["phase"], "refused", "{receipt:#}");
        assert_eq!(receipt["exec_observed"], false);
        assert_eq!(receipt["outcome"]["kind"], "refused");
        assert_eq!(
            receipt["outcome"]["error"]["code"], "missing_capability",
            "{profile}: {receipt:#}"
        );
        assert_eq!(
            taken.identity(),
            identity,
            "{profile}: the jail touched a directory it did not create"
        );
    }
}

/// L03.6, the behaviour its recorded limit leaves provable: a preferred pids
/// ceiling with no execution leaf (here: the leaf's name taken, as above;
/// the pids-controller-absent trigger itself needs the shared user-manager
/// tree reconfigured) is recorded absent — `required` false, `applied`
/// false, null mechanism, scope and hit — with the reason in the native
/// details and a wrapper `limit` note in the trace, and the run proceeds.
#[test]
fn l03_a_preferred_pids_ceiling_without_a_leaf_is_recorded_absent_and_the_run_proceeds() {
    if !common::live() {
        return;
    }
    let id = attempt_id();
    let _taken = TakenLeaf::take(&id);
    let (jail, workspace) = case("tool");
    let marker = workspace.join("target-ran");
    let jail = jail.args(["--attempt-id", &id]).target([
        "/bin/sh",
        "-c",
        &format!(": > {}", marker.display()),
    ]);
    let mut attempt = Attempt::start(jail, true);
    let prepared = attempt.await_kind("prepared");
    let digest = attempt.receipt()["policy"]["digest"]
        .as_str()
        .expect("a policy digest")
        .to_owned();
    assert_eq!(prepared["attempt_id"], id.as_str());
    attempt.release(&id, &digest);
    let terminal = attempt.await_terminal();
    let (run, _) = attempt.finish();
    assert_eq!(terminal["kind"], "settled");
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(marker.exists(), "the run did not proceed");
    let receipt = final_receipt(&run);
    let pids = limit_row(&receipt, "pids");
    assert_eq!(pids["required"], false, "{pids:#}");
    assert_eq!(pids["applied"], false, "{pids:#}");
    for key in ["mechanism", "scope", "hit"] {
        assert!(pids[key].is_null(), "{key}: {pids:#}");
    }
    assert!(
        details(&receipt)["execution_cgroup"]["unavailable"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "{:#}",
        details(&receipt)
    );
    let limit_notes: Vec<Value> = notes(&run)
        .into_iter()
        .filter(|fields| fields["kind"] == "limit")
        .collect();
    assert!(
        limit_notes
            .iter()
            .any(|fields| fields.to_string().contains("pids")),
        "no wrapper note explains the unapplied pids ceiling: {limit_notes:?}"
    );
}

// ===========================================================================
// L04: the execution deadline's clock (L04.4, L04.5, L04.6)
// ===========================================================================

/// An `LD_PRELOAD` shim over libc's `clock_gettime`: once the trigger file
/// exists, it adds a fixed offset to one clock id only, in every process
/// that loads it. The supervisor reads its clocks through libc, so this makes
/// CLOCK_BOOTTIME, CLOCK_MONOTONIC and CLOCK_REALTIME differ inside the jail
/// on a host where they do not otherwise (never suspended, clock never set).
/// The test's own clocks are not shifted.
const SHIM: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
static int (*real)(clockid_t, struct timespec *);
static const char *trigger;
static int shifted = -1;
static long long offset;
static volatile int fired;
__attribute__((constructor)) static void init(void) {
    real = (int (*)(clockid_t, struct timespec *))dlsym(RTLD_NEXT, "clock_gettime");
    trigger = getenv("OURO_B3_CLOCK_TRIGGER");
    const char *id = getenv("OURO_B3_CLOCK_ID");
    const char *ns = getenv("OURO_B3_CLOCK_OFFSET_NS");
    if (id) shifted = atoi(id);
    if (ns) offset = atoll(ns);
}
int clock_gettime(clockid_t id, struct timespec *ts) {
    int rc = real(id, ts);
    if (rc != 0 || id != shifted || !trigger) return rc;
    if (!fired && access(trigger, F_OK) == 0) fired = 1;
    if (!fired) return rc;
    long long total = (long long)ts->tv_sec * 1000000000LL + ts->tv_nsec + offset;
    ts->tv_sec = total / 1000000000LL;
    ts->tv_nsec = total % 1000000000LL;
    return rc;
}
"#;

/// Build the shim with the host's compiler into `dir`.
fn build_shim(dir: &Path) -> PathBuf {
    let source = dir.join("clock-shim.c");
    let library = dir.join("clock-shim.so");
    std::fs::write(&source, SHIM).expect("the shim source");
    let output = std::process::Command::new("/usr/bin/gcc")
        .args(["-shared", "-fPIC", "-O2", "-o"])
        .arg(&library)
        .arg(&source)
        .arg("-ldl")
        .output()
        .expect("gcc runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    library
}

/// A jail whose every process preloads the clock shim: once `trigger`
/// exists, CLOCK id `clock` reads `offset_ns` later than it is.
fn shimmed(jail: Jail, trigger: &Path, clock: libc::clockid_t, offset_ns: i64) -> Jail {
    let library = build_shim(jail.root());
    jail.timeout(Duration::from_secs(120))
        .env("LD_PRELOAD", &library)
        .env("OURO_B3_CLOCK_TRIGGER", trigger)
        .env("OURO_B3_CLOCK_ID", clock.to_string())
        .env("OURO_B3_CLOCK_OFFSET_NS", offset_ns.to_string())
}

/// What a shifted wall run measured on the test's own (unshifted) clock.
struct ShiftedWall {
    /// From just before the release frame (the wall starts after it) to the
    /// terminal message.
    from_release: Duration,
    /// From the clock shift to the terminal message.
    from_shift: Duration,
    receipt: Value,
}

/// One gated run of `/bin/sleep 300` in `profile` under `wall`, with the shim
/// shifting `clock` by `offset_ns` from the moment exec is confirmed.
fn shifted_wall_run(
    profile: &str,
    wall: &str,
    clock: libc::clockid_t,
    offset_ns: i64,
) -> ShiftedWall {
    let (jail, _) = case(profile);
    let trigger = jail.root().join("clock-trigger");
    let jail = shimmed(jail, &trigger, clock, offset_ns)
        .args(["--limit", &format!("wall={wall}")])
        .target(["/bin/sleep", "300"]);
    let mut attempt = Attempt::start(jail, true);
    let released = release_now(&mut attempt);
    attempt.await_kind("exec_confirmed");
    let shifted = Instant::now();
    std::fs::write(&trigger, b"").expect("the trigger");
    let terminal = attempt.await_terminal();
    let (from_release, from_shift) = (released.elapsed(), shifted.elapsed());
    let (run, _) = attempt.finish();
    assert_eq!(terminal["kind"], "settled", "{profile}: {terminal}");
    ShiftedWall {
        from_release,
        from_shift,
        receipt: final_receipt(&run),
    }
}

fn scope_of(profile: &str) -> &'static str {
    if profile == "none" {
        "registered_boundary"
    } else {
        "attempt_tree"
    }
}

fn assert_wall_expired(profile: &str, receipt: &Value) {
    assert_verified(receipt, scope_of(profile));
    assert_eq!(
        receipt["outcome"]["cause"], "wall_expiry",
        "{profile}: {receipt:#}"
    );
    let wall = limit_row(receipt, "wall");
    assert_eq!(wall["hit"], true, "{profile}: {wall:#}");
    assert_eq!(
        wall["mechanism"], "boottime-deadline",
        "{profile}: {wall:#}"
    );
}

const HOUR_NS: i64 = 3_600_000_000_000;
const TWO_MINUTES_NS: i64 = 120_000_000_000;

/// L04.4 (the execution wall) and L04.6, for `tool` and for `none` (a
/// separate implementation): the wall deadline of a real run follows
/// CLOCK_BOOTTIME. A 20 s wall; right after exec the shim advances only
/// CLOCK_BOOTTIME by two minutes — what a suspend looks like to a process:
/// the boot clock moves, the monotonic clock does not. The wall expires at
/// once (within 8 s of the jump on the test's own clock), which a deadline on
/// CLOCK_MONOTONIC or CLOCK_REALTIME would not do for 20 s.
#[test]
fn l04_the_execution_wall_follows_the_boot_clock_across_a_suspend_sized_jump() {
    if !common::live() {
        return;
    }
    for profile in ["tool", "none"] {
        let run = shifted_wall_run(profile, "20s", libc::CLOCK_BOOTTIME, TWO_MINUTES_NS);
        assert_wall_expired(profile, &run.receipt);
        assert!(
            run.from_shift < Duration::from_secs(8),
            "{profile}: the wall ignored a two-minute CLOCK_BOOTTIME advance: it expired {:?} \
             after it",
            run.from_shift
        );
        eprintln!(
            "L04.4/L04.6 {profile}: wall expired {:?} after the boot clock advanced",
            run.from_shift
        );
    }
}

/// L04.5, for `tool` and `none`: the wall deadline ignores wall-clock
/// adjustments. A 6 s wall; right after exec the shim steps only
/// CLOCK_REALTIME by an hour forward, and in a second run an hour back. Both
/// walls expire on time: not before 6 s after the test's own instant taken
/// just before the release (a deadline on the stepped clock would expire at
/// once forward, or never backward; nothing may expire before its value),
/// and within the wall plus §9.3's budgets.
#[test]
fn l04_the_execution_wall_ignores_wall_clock_steps() {
    if !common::live() {
        return;
    }
    let wall = Duration::from_secs(6);
    for profile in ["tool", "none"] {
        for offset in [HOUR_NS, -HOUR_NS] {
            let run = shifted_wall_run(profile, "6s", libc::CLOCK_REALTIME, offset);
            assert_wall_expired(profile, &run.receipt);
            assert!(
                run.from_release >= wall && run.from_release < wall + STOP_BOUND,
                "{profile}: a {}h wall-clock step moved the 6 s wall: it expired {:?} after the \
                 release",
                offset / HOUR_NS,
                run.from_release
            );
            eprintln!(
                "L04.5 {profile}: {}h step, wall expired {:?} after the release",
                offset / HOUR_NS,
                run.from_release
            );
        }
    }
}

/// L04.4, the stop grace (§6.4 puts "stop budgets" on CLOCK_BOOTTIME), for
/// `tool` and `none`. The target catches SIGTERM and goes on, so after an
/// operator SIGTERM only the forced stop ends it, after the 2 s grace. The
/// moment the target reports that the cooperative SIGTERM reached it (the
/// supervisor records the grace's start before sending it), the shim advances
/// only CLOCK_BOOTTIME by two minutes: a grace on the boot clock is over at
/// once and the target is SIGKILLed within a second of the jump; a grace on
/// CLOCK_MONOTONIC would still wait out its ~2 s.
#[test]
fn l04_the_stop_grace_follows_the_boot_clock() {
    if !common::live() {
        return;
    }
    for profile in ["tool", "none"] {
        let (jail, workspace) = case(profile);
        let trigger = jail.root().join("clock-trigger");
        let caught = workspace.join("caught-term");
        let jail = shimmed(jail, &trigger, libc::CLOCK_BOOTTIME, TWO_MINUTES_NS).target([
            PYTHON,
            "-c",
            TREE,
            "catch",
            caught.to_str().expect("UTF-8"),
        ]);
        let mut attempt = Attempt::start(jail, false);
        attempt.await_kind("exec_confirmed");
        let tree = started_tree(&attempt.receipt());
        poll_until(
            "the target to catch SIGTERM",
            Duration::from_secs(10),
            || {
                signal_mask(tree.launcher_pid, "SigCgt")
                    .is_some_and(|mask| mask & bit(libc::SIGTERM) != 0)
                    .then_some(())
            },
        );
        signal_supervisor(&attempt, libc::SIGTERM);
        poll_until(
            "the cooperative SIGTERM to reach the target",
            Duration::from_secs(10),
            || caught.exists().then_some(()),
        );
        let shifted = Instant::now();
        std::fs::write(&trigger, b"").expect("the trigger");
        let Some(took) = await_death_by(&tree.launcher, shifted, STOP_BOUND) else {
            attempt.fail(&format!("{profile}: the target outlived the forced stop"));
        };
        if await_death_by(&tree.descendant, shifted, STOP_BOUND).is_none() {
            attempt.fail(&format!(
                "{profile}: the descendant outlived the forced stop"
            ));
        }
        let terminal = attempt.await_terminal();
        let (run, _) = attempt.finish();
        assert_eq!(terminal["kind"], "settled", "{profile}: {terminal}");
        let receipt = final_receipt(&run);
        assert_verified(&receipt, scope_of(profile));
        assert_eq!(receipt["outcome"]["cause"], "operator_signal");
        assert!(
            took < Duration::from_secs(1),
            "{profile}: the stop grace ignored a two-minute CLOCK_BOOTTIME advance: the forced \
             stop came {took:?} after it"
        );
        eprintln!("L04.4 {profile}: forced stop {took:?} after the boot clock advanced");
    }
}

/// L04.4, the preparation budget (§8.2's 30 s, on CLOCK_BOOTTIME by §6.4),
/// for `tool` and `none`. The owner binds the attempt id, so the execution
/// leaf's path is known in advance; the shim's trigger is that path, so the
/// boot clock alone jumps two minutes the moment the supervisor creates its
/// leaf, in the middle of preparation. The attempt refuses before `prepared`
/// with `prepare_timeout` and remediation `retry` (not a host-setup failure of
/// whatever step was waiting when the budget ran out); a preparation budget
/// on CLOCK_MONOTONIC would reach `prepared`.
#[test]
fn l04_the_preparation_budget_follows_the_boot_clock() {
    if !common::live() {
        return;
    }
    for profile in ["tool", "none"] {
        let id = attempt_id();
        // SAFETY: getuid takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        let leaf = ouro_jail::platform::linux::cgroup::delegated_root(uid)
            .expect("the reference host delegates a cgroup subtree")
            .join(format!("ouro-{id}.leaf"));
        let (jail, _) = case(profile);
        let jail = shimmed(jail, &leaf, libc::CLOCK_BOOTTIME, TWO_MINUTES_NS)
            .args(["--attempt-id", &id])
            .target(["/bin/true"]);
        let mut attempt = Attempt::start(jail, true);
        let Some(first) = attempt.next() else {
            attempt.fail(&format!("{profile}: no control message at all"));
        };
        if first["kind"] != "refused" {
            attempt.fail(&format!(
                "{profile}: preparation went on past its budget: {first}"
            ));
        }
        let (run, _) = attempt.finish();
        let _ = gc_output(&run);
        let receipt = final_receipt(&run);
        let error = &receipt["outcome"]["error"];
        eprintln!("L04.4 preparation {profile}: refused with {error}");
        assert_eq!(run.code(), Some(125), "{profile}: {}", run.stderr_text());
        assert_eq!(error["code"], "prepare_timeout", "{profile}: {receipt:#}");
        assert_eq!(
            error["remediation_category"], "retry",
            "{profile}: {error:#}"
        );
        assert!(
            !leaf.exists(),
            "{profile}: the attempt's leaf was left behind"
        );
    }
}

// ===========================================================================
// C02.5: a cleanup interrupted by the supervisor's death
// ===========================================================================

const LAUNCH_PROFILE: &str = r#"
name = "fixture"
jail = "tool"
state_var = "FIX_HOME"
home_is_state = true
"#;

/// The target: fill `$FIX_HOME/many` with `n` files, say so, and exit 0 on
/// SIGUSR1.
const FILL: &str = r#"
import os, signal, sys
n = int(sys.argv[1])
d = os.environ["FIX_HOME"] + "/many"
os.mkdir(d)
for i in range(n):
    open(d + "/" + str(i), "w").close()
signal.signal(signal.SIGUSR1, lambda *_: os._exit(0))
with open(sys.argv[2] + ".tmp", "w") as f:
    f.write(str(n))
os.rename(sys.argv[2] + ".tmp", sys.argv[2])
while True:
    signal.pause()
"#;

const FILL_SIZE: usize = 40_000;

/// An inotify watch for deletions in one directory.
struct Deletions(OwnedFd);

impl Deletions {
    fn watch(dir: &Path) -> Deletions {
        // SAFETY: inotify_init1 takes flags only.
        let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        assert!(raw >= 0, "{}", std::io::Error::last_os_error());
        // SAFETY: `raw` is a fresh descriptor this process owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).expect("a path");
        // SAFETY: a live inotify descriptor and a NUL-terminated path.
        let wd = unsafe { libc::inotify_add_watch(fd.as_raw_fd(), path.as_ptr(), libc::IN_DELETE) };
        assert!(wd >= 0, "{}", std::io::Error::last_os_error());
        Deletions(fd)
    }

    /// Block until the first deletion, up to `within`.
    fn first(&self, within: Duration) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = i32::try_from(within.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: one live pollfd for the duration of the call.
        unsafe { libc::poll(&raw mut pfd, 1, millis) > 0 }
    }
}

/// C02.5: a vendor-state cleanup interrupted by the supervisor's death stays
/// pending, and `gc` resumes it. A launch-profile `tool` run fills its vendor
/// state with 40,000 files; the target exits; the moment the supervisor's
/// cleanup deletes the first of them (inotify), the test SIGKILLs the real
/// supervisor. The durable receipt is the settled one with `state_cleanup`
/// `pending`, and part of the vendor state is still there. `gc` then
/// finishes the removal and records `complete` in the receipt (one revision
/// later) and in jail state.
#[test]
fn c02_a_cleanup_interrupted_by_the_supervisors_death_stays_pending_and_gc_resumes_it() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().expect("a private jail harness");
    let launch = jail.config_dir().join("launch");
    private_dir(&launch);
    let profile = launch.join("fixture.toml");
    std::fs::write(&profile, LAUNCH_PROFILE).expect("the launch profile");
    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o600))
        .expect("an operator-only launch profile");
    let workspace = jail.root().join("workspace");
    private_dir(&workspace);
    let ready = workspace.join("filled");
    let jail = jail
        .arg("run")
        .arg("--workspace")
        .arg(&workspace)
        .args(["--launch", "fixture", "--observe", "off"])
        .receipt()
        .trace()
        .timeout(Duration::from_secs(180))
        .target([
            PYTHON,
            "-c",
            FILL,
            &FILL_SIZE.to_string(),
            ready.to_str().expect("UTF-8"),
        ]);
    let data = jail.data_dir();
    let mut attempt = Attempt::start(jail, false);
    let prepared = attempt.await_kind("prepared");
    let root = data
        .join("attempts")
        .join(prepared["attempt_id"].as_str().expect("an attempt id"));
    attempt.await_kind("exec_confirmed");
    let launcher = pidfd(pid_at(&attempt.receipt(), "launcher_pid"));
    poll_until("the vendor state to fill", Duration::from_secs(120), || {
        ready.exists().then_some(())
    });
    let many = root.join("vendor-state").join("many");
    let deletions = Deletions::watch(&many);
    kill_by_pidfd(&launcher, libc::SIGUSR1);
    if !deletions.first(Duration::from_secs(30)) {
        attempt.fail("the supervisor never started its cleanup");
    }
    let supervisor = pidfd(attempt.pid());
    kill_by_pidfd(&supervisor, libc::SIGKILL);
    let (run, _) = attempt.finish();
    // What the dead supervisor left, read before gc; gc runs before anything
    // is asserted, so a failure leaves no leaf in the shared subtree.
    let left = std::fs::read_dir(&many).map_or(0, Iterator::count);
    let read = |name: &str| -> Value {
        serde_json::from_slice(&std::fs::read(root.join(name)).expect(name)).expect("JSON")
    };
    let before = common::checked_receipt(read("jail.json"));
    let (output, report) = gc(&run);
    let after = common::checked_receipt(read("jail.json"));

    assert_eq!(run.signal(), Some(libc::SIGKILL));
    assert!(
        left > 0 && left < FILL_SIZE,
        "the kill did not land inside the cleanup: {left} of {FILL_SIZE} entries left"
    );
    assert_eq!(before["phase"], "settled", "{before:#}");
    assert_eq!(before["lifetime"]["tree_empty"], true);
    assert_eq!(before["state_cleanup"], "pending", "{before:#}");
    let revision = before["revision"].as_u64().expect("a revision");
    assert!(output.status.success(), "{report:#}");
    assert!(
        report["entries"].as_array().is_some_and(|entries| entries
            .iter()
            .any(|e| e["action"] == "removed_vendor_state")),
        "{report:#}"
    );
    assert!(!root.join("vendor-state").exists(), "{report:#}");
    assert_eq!(after["state_cleanup"], "complete", "{after:#}");
    assert_eq!(after["revision"].as_u64(), Some(revision + 1));
    assert_eq!(read("jail-state.json")["state_cleanup"], "complete");
    eprintln!("C02.5: {left} of {FILL_SIZE} entries were left when the supervisor died");
}

/// L04.4 (the gate budget): §6.4 puts the preparation and gate budgets on
/// CLOCK_BOOTTIME too. A gated `tool` run is never released; right after
/// `prepared` the shim advances only CLOCK_BOOTTIME by two minutes, past the
/// 60-second gate budget. The run refuses with `prepare_timeout` at once,
/// which a gate wait on CLOCK_MONOTONIC would not do for 60 s. "At once" is
/// bounded at 700 ms of the jump: the wait's first poll began when `prepared`
/// was sent, just before the jump, and the supervisor re-reads its deadline
/// when that poll returns (every 250 ms, §8.2); a wait that re-read it only
/// at the older one-second poll cap would refuse about a second after the
/// jump and fail this bound.
#[test]
fn l04_the_gate_wait_follows_the_boot_clock() {
    if !common::live() {
        return;
    }
    let (jail, _) = case("tool");
    let library = build_shim(jail.root());
    let trigger = jail.root().join("clock-trigger");
    let jail = jail
        .timeout(Duration::from_secs(120))
        .env("LD_PRELOAD", &library)
        .env("OURO_B3_CLOCK_TRIGGER", &trigger)
        .env("OURO_B3_CLOCK_ID", libc::CLOCK_BOOTTIME.to_string())
        .env(
            "OURO_B3_CLOCK_OFFSET_NS",
            (2 * 60_000_000_000_i64).to_string(),
        )
        .target(["/bin/true"]);
    let mut attempt = Attempt::start(jail, true);
    attempt.await_kind("prepared");
    let jumped = Instant::now();
    std::fs::write(&trigger, b"").expect("the trigger");
    let terminal = attempt.await_terminal();
    let took = jumped.elapsed();
    let (run, _) = attempt.finish();
    assert_eq!(terminal["kind"], "refused", "{terminal}");
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    let receipt = final_receipt(&run);
    assert_eq!(
        receipt["outcome"]["error"]["code"], "prepare_timeout",
        "{receipt:#}"
    );
    assert!(
        took < GATE_RECHECK_BOUND,
        "the gate wait did not act on a two-minute CLOCK_BOOTTIME advance within \
         {GATE_RECHECK_BOUND:?}: it expired {took:?} after it"
    );
    eprintln!("L04.4 gate: refused {took:?} after the boot clock advanced");
}
