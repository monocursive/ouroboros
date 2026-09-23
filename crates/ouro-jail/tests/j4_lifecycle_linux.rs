//! J4 lifecycle (§9.3): a killed supervisor takes down everything in its
//! execution cgroup, not only bubblewrap's outer process.
//!
//! Measured on the reference host (2026-09-23, doctor's agent probe killed at
//! swept points): bubblewrap's namespace init arms its own parent-death signal
//! late in its startup, and before that waits on an eventfd only the outer
//! process writes. A supervisor killed in that window made the watcher kill
//! the outer process, and the init stayed alive on pid 1 (seen blocked on the
//! eventfd, and as an init waiting on its child) until something ran `gc`.

#![cfg(target_os = "linux")]

use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ouro_fixture::harness::{self, Jail};
use ouro_jail::platform::linux::cgroup::ExecutionCgroup;
use ouro_jail::platform::linux::{exec, identity, probe};
use ouro_jail::policy::LimitsSnapshot;
use serde_json::Value;

mod common;

fn live() -> bool {
    if !common::live() {
        return false;
    }
    let leaf = probe::run_one(
        "cgroup_delegated_leaf",
        &harness::jail_path(),
        Path::new("bwrap"),
    );
    if leaf.status != probe::ProbeStatus::Available {
        harness::skip_or_fail(&format!(
            "J4 lifecycle needs a delegated user scope with a usable leaf: {}",
            leaf.evidence
        ));
        return false;
    }
    true
}

fn sleeper() -> Child {
    Command::new("/usr/bin/sleep")
        .arg("600")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sleep")
}

fn exited(child: &mut Child, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn members(cgroup_dir: &Path) -> Vec<i32> {
    std::fs::read_to_string(cgroup_dir.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.parse().ok())
        .collect()
}

/// The watcher's own protocol (fds 3, 4, 5, and 6 for the leaf's
/// `cgroup.kill`), driven with stand-ins: the leaf holds the backend and a
/// second process that, like bubblewrap's init in that window, has no
/// parent-death signal and is not the backend.
struct Stand {
    leaf: ExecutionCgroup,
    backend: Child,
    stranded: Child,
    supervisor: Child,
    watcher: Child,
}

impl Stand {
    fn start() -> Self {
        let limits = LimitsSnapshot {
            wall: None,
            pids: None,
            mem: None,
            cpu: None,
        };
        let leaf = ExecutionCgroup::create(&limits).expect("a leaf in the delegated scope");
        let backend = sleeper();
        let stranded = sleeper();
        leaf.place(backend.id() as i32).expect("place the backend");
        leaf.place(stranded.id() as i32)
            .expect("place the stranded process");
        // Only the stand-in supervisor's death matters to the watcher.
        let supervisor = sleeper();
        let (ready_r, ready_w) = exec::pipe().unwrap();
        let kill = std::fs::OpenOptions::new()
            .write(true)
            .open(leaf.path().join("cgroup.kill"))
            .expect("the leaf's cgroup.kill");
        let mut fds = exec::FdMap::new();
        fds.add(identity::pidfd_open(supervisor.id() as i32).unwrap(), 3)
            .unwrap();
        fds.add(identity::pidfd_open(backend.id() as i32).unwrap(), 4)
            .unwrap();
        fds.add(ready_w, 5).unwrap();
        fds.add(OwnedFd::from(kill), 6).unwrap();
        let mut command = Command::new(harness::jail_path());
        command
            .args(["__watch", "--cgroup-kill-fd", "6"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        fds.apply(&mut command);
        let watcher = command.spawn().expect("the watcher");
        drop(fds);
        let mut pfd = libc::pollfd {
            fd: ready_r.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd; a one-byte read into a live byte.
        let ready = unsafe {
            let mut byte = 0u8;
            libc::poll(&raw mut pfd, 1, 5000) == 1
                && libc::read(ready_r.as_raw_fd(), (&raw mut byte).cast(), 1) == 1
                && byte == 1
        };
        assert!(ready, "the watcher reported ready");
        Stand {
            leaf,
            backend,
            stranded,
            supervisor,
            watcher,
        }
    }

    /// (backend ended, stranded ended, watcher ended), then cleanup.
    fn outcome(mut self) -> (bool, bool, bool) {
        let backend = exited(&mut self.backend, Duration::from_secs(3));
        let stranded = exited(&mut self.stranded, Duration::from_secs(3));
        let watcher = exited(&mut self.watcher, Duration::from_secs(3));
        for child in [
            &mut self.backend,
            &mut self.stranded,
            &mut self.supervisor,
            &mut self.watcher,
        ] {
            let _ = child.kill();
            let _ = child.wait();
        }
        drop(self.leaf);
        (backend, stranded, watcher)
    }
}

#[test]
fn j4_supervisor_death_kills_everything_in_the_execution_cgroup() {
    if !live() {
        return;
    }
    let mut stand = Stand::start();
    stand.supervisor.kill().unwrap();
    stand.supervisor.wait().unwrap();
    let (backend, stranded, watcher) = stand.outcome();
    assert!(
        backend,
        "the watcher kills the backend when the supervisor dies"
    );
    assert!(
        stranded,
        "a process in the execution cgroup outlived the killed supervisor: \
         the watcher must kill the whole leaf, not only the backend"
    );
    assert!(watcher, "the watcher exits once it has acted");
}

/// Supervisor death also fires bubblewrap's own `--die-with-parent`, so the
/// watcher can wake to find the backend gone as well. A dead supervisor
/// decides: the leaf is killed even when the backend ended in the same
/// instant. Deterministic: the watcher is stopped while both die.
#[test]
fn j4_a_supervisor_and_backend_dying_together_still_kill_the_leaf() {
    if !live() {
        return;
    }
    let mut stand = Stand::start();
    let watcher = stand.watcher.id() as i32;
    // SAFETY: signalling the watcher this test started.
    assert_eq!(unsafe { libc::kill(watcher, libc::SIGSTOP) }, 0);
    stand.supervisor.kill().unwrap();
    stand.supervisor.wait().unwrap();
    stand.backend.kill().unwrap();
    stand.backend.wait().unwrap();
    // SAFETY: as above.
    assert_eq!(unsafe { libc::kill(watcher, libc::SIGCONT) }, 0);
    let (_, stranded, watcher_ended) = stand.outcome();
    assert!(
        stranded,
        "the watcher saw the backend's end first and left the leaf alive \
         although the supervisor was dead"
    );
    assert!(watcher_ended, "the watcher exits once it has acted");
}

/// The product wires it: a contained run's watcher holds that run's leaf's
/// `cgroup.kill`, and killing the supervisor empties the leaf.
#[test]
fn j4_a_contained_runs_watcher_holds_its_leafs_kill_file() {
    if !live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let ws = jail.root().join("workspace");
    std::fs::create_dir(&ws).unwrap();
    let marker = ws.join("running");
    let code = format!(
        "import time; open({:?},'w').close(); time.sleep(30)",
        marker.to_str().unwrap()
    );
    let mut spawned = jail
        .arg("run")
        .arg("--workspace")
        .arg(&ws)
        .control()
        .gate()
        .receipt()
        .target(["/usr/bin/python3", "-c", &code])
        .spawn()
        .unwrap();
    let prepared = spawned.owner().await_prepared().unwrap();
    let receipt = spawned.receipt_value().unwrap();
    let details = &receipt["lifetime"]["native"]["details"];
    let leaf = PathBuf::from(
        details["execution_cgroup"]["path"]
            .as_str()
            .expect("a contained run registers its leaf"),
    );
    let watcher = details["watcher_pid"]
        .as_i64()
        .expect("a contained run records its watcher") as i32;
    let cmdline = std::fs::read(format!("/proc/{watcher}/cmdline")).unwrap_or_default();
    let argv: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
    let held = std::fs::read_link(format!("/proc/{watcher}/fd/6")).ok();
    assert_eq!(
        held.as_deref(),
        Some(leaf.join("cgroup.kill").as_path()),
        "the watcher holds its leaf's cgroup.kill as fd 6 (argv {:?})",
        argv.iter()
            .map(|a| String::from_utf8_lossy(a))
            .collect::<Vec<_>>()
    );
    assert!(
        argv.windows(2)
            .any(|w| w[0] == b"--cgroup-kill-fd" && w[1] == b"6"),
        "the watcher is told which descriptor is the leaf's kill file"
    );

    spawned
        .owner()
        .release(
            &harness::gate::Release::Valid,
            prepared["attempt_id"].as_str().unwrap(),
            receipt["policy"]["digest"].as_str().unwrap(),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(marker.exists(), "the target ran");
    assert!(!members(&leaf).is_empty(), "the leaf holds the tree");
    let supervisor = identity::pidfd_open(spawned.pid() as i32).unwrap();
    identity::pidfd_send_signal(supervisor.as_raw_fd(), libc::SIGKILL).unwrap();
    let run = spawned.wait().unwrap();
    assert_eq!(run.signal(), Some(libc::SIGKILL));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !members(&leaf).is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let left = members(&leaf);
    assert!(
        left.is_empty(),
        "processes in the leaf outlived the killed supervisor: {left:?}"
    );
    let last: Option<Value> = run.receipts().last().cloned();
    assert_eq!(
        last.as_ref().map(|r| r["phase"].clone()),
        Some(Value::from("enforced")),
        "a killed supervisor settles nothing"
    );
    // The retained, now empty leaf is gc's to remove; this test only made it.
    let _ = std::fs::remove_dir(&leaf);
}
