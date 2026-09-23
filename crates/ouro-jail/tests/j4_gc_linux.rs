//! J4 slice G, live on the reference host: `gc` reconciles what a dead
//! supervisor left in its execution cgroup (jail-v1 §9.3, §14.2, §15 C03).
//!
//! Every attempt here is a real `ouro-jail run` whose supervisor this test
//! kills with SIGKILL, exactly as `conformance_j3_none::l02_…` does, and
//! every `gc` is the real binary over that run's private state root. The
//! only cgroups touched are the leaves those runs created (checked by inode)
//! and one look-alike this test creates at a leaf's path; the only processes
//! touched are the runs' own trees and the test's own children.
//!
//! PID reuse cannot be forced unprivileged on the stock host (J4 decision
//! S1): "never signals an unrelated process" is shown by identity mismatch.
//! The recorded owner names a live, unrelated process of this test whose
//! birth time differs from the record (a recycled pid, as the kernel would
//! produce it), and that process must neither be signalled nor keep `gc`
//! from ending the positively identified orphan; when the record matches it
//! exactly, the owner is alive and `gc` retains everything.
#![cfg(target_os = "linux")]

use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ouro_fixture::harness::{self, Jail, Run, Spawned};
use ouro_jail::platform::linux::{identity, probe, watch};
use serde_json::{Value, json};

mod common;

const PYTHON: &str = "/usr/bin/python3";

// ---------------------------------------------------------------------------
// Preconditions and helpers
// ---------------------------------------------------------------------------

/// A delegated user scope with a usable leaf, and the fixture interpreter.
fn live() -> bool {
    let leaf = probe::run_one(
        "cgroup_delegated_leaf",
        &harness::jail_path(),
        Path::new("bwrap"),
    );
    if leaf.status != probe::ProbeStatus::Available {
        harness::skip_or_fail(&format!(
            "slice G needs a delegated user scope with a usable leaf: {}",
            leaf.evidence
        ));
        return false;
    }
    if !Path::new(PYTHON).is_file() {
        harness::skip_or_fail("the orphan fixtures are python3 scripts");
        return false;
    }
    true
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn receipt_in_phase(spawned: &Spawned, phase: &str) -> Value {
    let mut latest = Value::Null;
    wait_for(&format!("a {phase} receipt"), || {
        latest = spawned.receipt_value().unwrap_or(Value::Null);
        latest["phase"] == phase
    });
    latest
}

fn leaf_of(receipt: &Value) -> (PathBuf, u64) {
    let leaf = &receipt["lifetime"]["native"]["details"]["execution_cgroup"];
    (
        PathBuf::from(leaf["path"].as_str().expect("a leaf path")),
        leaf["inode"].as_u64().expect("a leaf inode"),
    )
}

fn populated(cgroup_dir: &Path) -> bool {
    std::fs::read_to_string(cgroup_dir.join("cgroup.events"))
        .expect("cgroup.events is readable")
        .lines()
        .any(|line| line == "populated 1")
}

fn members(cgroup_dir: &Path) -> Vec<i32> {
    std::fs::read_to_string(cgroup_dir.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.parse().ok())
        .collect()
}

fn inode(path: &Path) -> Option<u64> {
    std::fs::symlink_metadata(path).ok().map(|meta| meta.ino())
}

/// Removes, when the test ends however it ends, the leaf a run left and the
/// look-alike a test put at its path, and nothing else: the directory is
/// emptied and removed only while its inode is one this test knows.
struct LeafGuard {
    path: PathBuf,
    inodes: Vec<u64>,
}

impl LeafGuard {
    fn new(path: &Path, inode: u64) -> LeafGuard {
        LeafGuard {
            path: path.to_path_buf(),
            inodes: vec![inode],
        }
    }
}

impl Drop for LeafGuard {
    fn drop(&mut self) {
        let Some(now) = inode(&self.path) else { return };
        if !self.inodes.contains(&now) {
            return;
        }
        if populated(&self.path) {
            let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
            let deadline = Instant::now() + Duration::from_secs(5);
            while populated(&self.path) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        remove_cgroup_tree(&self.path);
    }
}

/// Removes an empty cgroup and the empty cgroups under it, deepest first.
fn remove_cgroup_tree(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                remove_cgroup_tree(&entry.path());
            }
        }
    }
    let _ = std::fs::remove_dir(dir);
}

/// Reads a pid a fixture published with an atomic rename.
fn written_pid(path: &Path) -> i32 {
    wait_for(&format!("{}", path.display()), || path.exists());
    std::fs::read_to_string(path)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// A live orphan: a `none` run with observation off whose target and one
/// descendant sleep in the execution leaf with their stdio detached, and
/// whose supervisor this test then kills with SIGKILL (the L02 setup). The
/// target dies with its supervisor (the launcher's parent-death signal
/// survives its exec); the descendant does not, and is the orphan: nothing
/// ends it (§8.2, no second watchdog) until `gc` does.
struct Orphan {
    run: Run,
    leaf: PathBuf,
    inode: u64,
    descendant: std::os::fd::OwnedFd,
    _guard: LeafGuard,
}

impl Orphan {
    fn new() -> Orphan {
        Orphan::nested(0)
    }

    /// An orphan whose descendant first makes `depth` nested cgroups inside
    /// its own leaf and moves itself into the deepest: what any same-uid
    /// process in a `none` leaf may do (no controller is enabled in it).
    fn nested(depth: usize) -> Orphan {
        let jail = Jail::new().expect("a private harness");
        let workspace = jail.root().join("workspace");
        std::fs::create_dir(&workspace).expect("the workspace");
        let target_file = jail.root().join("target.pid");
        let descendant_file = jail.root().join("descendant.pid");
        let code = format!(
            "import os, time\n\
             def publish(path):\n\
             \x20   open(path + '.tmp', 'w').write(str(os.getpid()))\n\
             \x20   os.rename(path + '.tmp', path)\n\
             null = os.open('/dev/null', os.O_RDWR)\n\
             for fd in (0, 1, 2): os.dup2(null, fd)\n\
             if os.fork() == 0:\n\
             \x20   path = '/sys/fs/cgroup' + open('/proc/self/cgroup').read().split('::', 1)[1].strip()\n\
             \x20   for level in range({depth}):\n\
             \x20       path = path + '/n%d' % level\n\
             \x20       os.mkdir(path)\n\
             \x20   if {depth}: open(path + '/cgroup.procs', 'w').write('0')\n\
             \x20   publish({descendant:?})\n\
             \x20   time.sleep(120)\n\
             \x20   os._exit(0)\n\
             while not os.path.exists({descendant:?}): time.sleep(0.01)\n\
             publish({target:?})\n\
             time.sleep(120)\n",
            descendant = descendant_file.to_str().unwrap(),
            target = target_file.to_str().unwrap(),
            depth = depth,
        );
        let mut spawned = jail
            .arg("run")
            .arg("--profile")
            .arg("none")
            .arg("--observe")
            .arg("off")
            .arg("--workspace")
            .arg(&workspace)
            .receipt()
            .timeout(Duration::from_secs(60))
            .target([PYTHON, "-c", &code])
            .spawn()
            .expect("the jail starts");
        let target_pid = written_pid(&target_file);
        let descendant_pid = written_pid(&descendant_file);
        let enforced = receipt_in_phase(&spawned, "enforced");
        let (leaf, leaf_inode) = leaf_of(&enforced);
        let guard = LeafGuard::new(&leaf, leaf_inode);
        let descendant = identity::pidfd_open(descendant_pid).expect("the live descendant");
        let in_leaf = members(&leaf);
        assert!(in_leaf.contains(&target_pid), "{in_leaf:?}");
        let mut innermost = leaf.clone();
        for level in 0..depth {
            innermost.push(format!("n{level}"));
        }
        let inner = members(&innermost);
        assert!(inner.contains(&descendant_pid), "{inner:?}");
        spawned
            .kill()
            .expect("the harness kills its own supervisor");
        let run = spawned
            .wait()
            .expect("the harness collects the dead supervisor");
        assert_eq!(run.signal(), Some(libc::SIGKILL), "{}", run.stderr_text());
        // The accepted unknown of §8.2: no watchdog, the orphan still runs.
        assert!(populated(&leaf));
        assert!(!watch::readable(descendant.as_raw_fd()));
        Orphan {
            run,
            leaf,
            inode: leaf_inode,
            descendant,
            _guard: guard,
        }
    }

    fn attempt(&self) -> PathBuf {
        attempt_of(&self.run.data_dir)
    }

    fn orphan_alive(&self) -> bool {
        !watch::readable(self.descendant.as_raw_fd())
    }

    fn orphan_dead(&self) -> bool {
        watch::readable(self.descendant.as_raw_fd())
    }
}

fn attempt_of(data: &Path) -> PathBuf {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(data.join("attempts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
    entries.pop().unwrap()
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn write_json(path: &Path, value: &Value) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// The real `gc --json` over a run's state root: exit code, report, stderr.
fn gc(run: &Run, extra: &[&str]) -> (Option<i32>, Value, String) {
    let output = Command::new(harness::jail_path())
        .arg("gc")
        .args(extra)
        .arg("--json")
        .env("OURO_DATA_DIR", &run.data_dir)
        .env("OURO_CONFIG_DIR", run.data_dir.with_file_name("config"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let report: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("gc printed no JSON report ({error}): {stderr}"));
    (output.status.code(), report, stderr)
}

fn gc_actions(attempt: &Path) -> Vec<String> {
    read_json(&attempt.join("jail-state.json"))["gc_actions"]
        .as_array()
        .map(|actions| {
            actions
                .iter()
                .map(|action| action["action"].as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn text<'a>(report: &'a Value, key: &str) -> &'a str {
    report["entries"][0][key].as_str().unwrap_or("")
}

// ===========================================================================
// C03: the orphan of this boot is killed, verified empty and removed
// ===========================================================================

/// §14.2: "In the same boot, a populated, positively identified orphan
/// execution cgroup may be killed by this explicit GC invocation ... Record
/// `gc_terminated_orphan` and verify emptiness before deleting state." The
/// dry run reports and changes nothing; the real run ends the orphan through
/// `cgroup.kill` of the leaf whose inode the receipt registered, sees it
/// empty, removes it, and records each step in jail state (S6) without
/// rewriting the receipt. A second pass has nothing left to do.
#[test]
fn j4_c03_a_populated_orphan_leaf_of_this_boot_is_killed_verified_and_removed() {
    if !live() {
        return;
    }
    let orphan = Orphan::new();
    let attempt = orphan.attempt();
    let receipt = std::fs::read(attempt.join("jail.json")).unwrap();

    let (code, report, stderr) = gc(&orphan.run, &["--dry-run"]);
    assert_eq!(code, Some(0), "{stderr}\n{report:#}");
    assert_eq!(
        text(&report, "cgroup"),
        "would_terminate_orphan",
        "{report:#}"
    );
    assert!(orphan.orphan_alive(), "a dry run ended the orphan");
    assert_eq!(inode(&orphan.leaf), Some(orphan.inode));
    assert!(
        gc_actions(&attempt).is_empty(),
        "a dry run recorded an action"
    );

    let (code, report, stderr) = gc(&orphan.run, &[]);
    assert_eq!(code, Some(0), "{stderr}\n{report:#}");
    assert_eq!(
        text(&report, "cgroup"),
        "terminated_orphan_and_removed",
        "{report:#}"
    );
    assert!(text(&report, "owner").starts_with("dead"), "{report:#}");
    wait_for("the orphan's end", || orphan.orphan_dead());
    assert_eq!(
        inode(&orphan.leaf),
        None,
        "the verified-empty leaf is removed"
    );
    assert_eq!(
        gc_actions(&attempt),
        [
            "gc_terminating_orphan",
            "gc_terminated_orphan",
            "gc_removed_cgroup"
        ]
    );
    let state = read_json(&attempt.join("jail-state.json"));
    for action in state["gc_actions"].as_array().unwrap() {
        assert_eq!(
            action["execution_cgroup"]["inode"], orphan.inode,
            "{state:#}"
        );
    }
    assert_eq!(
        std::fs::read(attempt.join("jail.json")).unwrap(),
        receipt,
        "S6: gc never rewrites the supervisor's receipt"
    );

    let (code, report, stderr) = gc(&orphan.run, &[]);
    assert_eq!(code, Some(0), "{stderr}\n{report:#}");
    assert!(
        text(&report, "cgroup").contains("removed by gc"),
        "{report:#}"
    );
    assert_eq!(gc_actions(&attempt).len(), 3, "nothing more to record");
}

/// §14.2: "Never ... delete a directory solely because its name looks like"
/// the resource: after the orphan is gone, a different cgroup at the leaf's
/// path (emptied, removed and recreated, the only way cgroup v2 lets a path be
/// reused) holding a process of this test is neither killed nor removed.
#[test]
fn j4_c03_a_replaced_leaf_is_never_touched() {
    if !live() {
        return;
    }
    let mut orphan = Orphan::new();
    // Replace the leaf: end what it holds, remove it, make a look-alike.
    std::fs::write(orphan.leaf.join("cgroup.kill"), "1").unwrap();
    wait_for("the old leaf to empty", || !populated(&orphan.leaf));
    std::fs::remove_dir(&orphan.leaf).unwrap();
    std::fs::create_dir(&orphan.leaf).unwrap();
    let replacement = inode(&orphan.leaf).unwrap();
    assert_ne!(replacement, orphan.inode);
    orphan._guard.inodes.push(replacement);
    let mut bystander = Command::new("sleep").arg("120").spawn().unwrap();
    std::fs::write(orphan.leaf.join("cgroup.procs"), bystander.id().to_string()).unwrap();
    assert!(members(&orphan.leaf).contains(&(bystander.id() as i32)));

    for extra in [&["--dry-run"][..], &[][..]] {
        let (code, report, stderr) = gc(&orphan.run, extra);
        assert_eq!(code, Some(0), "{extra:?}: {stderr}\n{report:#}");
        let cgroup = text(&report, "cgroup");
        assert!(
            cgroup.starts_with("retained") && cgroup.contains("replaced"),
            "{extra:?}: {report:#}"
        );
        assert!(
            bystander.try_wait().unwrap().is_none(),
            "gc ended a process in a cgroup it does not own"
        );
        assert_eq!(
            inode(&orphan.leaf),
            Some(replacement),
            "gc removed the look-alike"
        );
        assert!(members(&orphan.leaf).contains(&(bystander.id() as i32)));
        assert!(gc_actions(&orphan.attempt()).is_empty());
    }
    bystander.kill().unwrap();
    bystander.wait().unwrap();
}

/// §14.2: "After host reboot, the old processes cannot be alive, but any
/// reused cgroup path must not be treated as the original resource." The
/// boot cannot be changed, so the records are: jail state and the receipt
/// both name another boot. The leaf at the recorded path (the very same
/// cgroup, populated) is then never killed, never removed, never probed as
/// the attempt's.
#[test]
fn j4_c03_a_simulated_reboot_never_targets_a_reused_cgroup() {
    if !live() {
        return;
    }
    let orphan = Orphan::new();
    let attempt = orphan.attempt();
    let other_boot = "00000000-0000-4000-8000-00000000b0b0";
    let mut state = read_json(&attempt.join("jail-state.json"));
    assert_ne!(state["owner"]["boot_id"], other_boot);
    state["owner"]["boot_id"] = json!(other_boot);
    write_json(&attempt.join("jail-state.json"), &state);
    let mut receipt = read_json(&attempt.join("jail.json"));
    receipt["process"]["identity"]["value"]["boot_id"] = json!(other_boot);
    write_json(&attempt.join("jail.json"), &receipt);

    for extra in [&["--dry-run"][..], &[][..]] {
        let (code, report, stderr) = gc(&orphan.run, extra);
        assert_eq!(code, Some(0), "{extra:?}: {stderr}\n{report:#}");
        assert!(
            text(&report, "cgroup").contains("another boot"),
            "{extra:?}: {report:#}"
        );
        assert!(
            text(&report, "owner").contains("another boot"),
            "{extra:?}: {report:#}"
        );
        assert!(
            orphan.orphan_alive(),
            "{extra:?}: a reused path was treated as the leaf"
        );
        assert_eq!(inode(&orphan.leaf), Some(orphan.inode));
        assert!(populated(&orphan.leaf));
        assert!(
            gc_actions(&attempt)
                .iter()
                .all(|action| !action.contains("orphan") && !action.contains("cgroup")),
            "{:?}",
            gc_actions(&attempt)
        );
    }
}

/// A process of this test that records every catchable signal it receives.
struct Bystander {
    child: std::process::Child,
    marker: PathBuf,
}

impl Bystander {
    fn new(dir: &Path) -> Bystander {
        let marker = dir.join("bystander.signals");
        let ready = dir.join("bystander.ready");
        let child = Command::new(PYTHON)
            .arg("-c")
            .arg(
                "import signal, sys, time\n\
                 marker, ready = sys.argv[1], sys.argv[2]\n\
                 def note(signo, frame):\n\
                 \x20   open(marker, 'a').write('%d\\n' % signo)\n\
                 for s in range(1, signal.NSIG):\n\
                 \x20   try: signal.signal(s, note)\n\
                 \x20   except (OSError, ValueError, RuntimeError): pass\n\
                 open(ready, 'w').write('1')\n\
                 while True: time.sleep(0.2)\n",
            )
            .arg(&marker)
            .arg(&ready)
            .spawn()
            .unwrap();
        wait_for("the bystander", || ready.exists());
        Bystander { child, marker }
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    fn assert_untouched(&mut self, label: &str) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "{label}: the bystander died"
        );
        let signals = std::fs::read_to_string(&self.marker).unwrap_or_default();
        assert!(
            signals.is_empty(),
            "{label}: the bystander got signals {signals:?}"
        );
    }
}

impl Drop for Bystander {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// §9.3: "never signal a PID recovered from a file without revalidating its
/// identity." The recorded owner is rewritten to name a live process of this
/// test. Exact birth identity: the owner is alive though it holds no lease,
/// so gc retains everything. A different birth time (the pid recycled): the
/// owner is dead, gc ends the positively identified orphan through its leaf,
/// and the process at the recycled pid is never signalled.
#[test]
fn j4_c03_a_stale_owner_pid_never_signals_an_unrelated_process() {
    if !live() {
        return;
    }
    let orphan = Orphan::new();
    let attempt = orphan.attempt();
    let mut bystander = Bystander::new(orphan.run.data_dir.parent().unwrap());
    let born = identity::start_time_ticks(bystander.pid()).unwrap();
    let boot = identity::boot_id().unwrap();

    // The record names the bystander exactly: an owner that is alive.
    let mut state = read_json(&attempt.join("jail-state.json"));
    assert_eq!(state["owner"]["boot_id"], boot.as_str(), "{state:#}");
    state["owner"] = json!({"pid": bystander.pid(), "boot_id": boot, "start_time_ticks": born});
    write_json(&attempt.join("jail-state.json"), &state);
    for extra in [&["--dry-run"][..], &[][..]] {
        let (code, report, stderr) = gc(&orphan.run, extra);
        assert_eq!(code, Some(0), "{extra:?}: {stderr}\n{report:#}");
        assert_eq!(text(&report, "action"), "retained", "{report:#}");
        assert!(text(&report, "reason").contains("alive"), "{report:#}");
        assert!(
            orphan.orphan_alive(),
            "{extra:?}: the live owner's tree was ended"
        );
        assert_eq!(inode(&orphan.leaf), Some(orphan.inode));
        bystander.assert_untouched("live owner");
    }

    // The same pid with another birth time: a recycled pid.
    state["owner"]["start_time_ticks"] = json!(born + 1);
    write_json(&attempt.join("jail-state.json"), &state);
    let (code, report, stderr) = gc(&orphan.run, &[]);
    assert_eq!(code, Some(0), "{stderr}\n{report:#}");
    assert!(text(&report, "owner").contains("reused"), "{report:#}");
    assert_eq!(
        text(&report, "cgroup"),
        "terminated_orphan_and_removed",
        "{report:#}"
    );
    wait_for("the orphan's end", || orphan.orphan_dead());
    assert_eq!(inode(&orphan.leaf), None);
    bystander.assert_untouched("recycled pid");
}

/// A receipt is the supervisor's record, but in `none` the same uid can
/// rewrite it. One that names another cgroup of this user (its real path,
/// device and inode, and a process in it) is still not an execution leaf by
/// name, so gc never pins it, never kills through it and never removes it.
#[test]
fn j4_c03_a_receipt_naming_another_cgroup_is_never_acted_on() {
    if !live() {
        return;
    }
    let orphan = Orphan::new();
    let attempt = orphan.attempt();
    let root = orphan.leaf.parent().unwrap().to_path_buf();
    let other = root.join(format!("ouro-j4gc-bystander-{}", std::process::id()));
    std::fs::create_dir(&other).unwrap();
    let _other_guard = LeafGuard::new(&other, inode(&other).unwrap());
    let mut bystander = Command::new("sleep").arg("120").spawn().unwrap();
    std::fs::write(other.join("cgroup.procs"), bystander.id().to_string()).unwrap();
    let meta = std::fs::metadata(&other).unwrap();
    let mut receipt = read_json(&attempt.join("jail.json"));
    let registration = &mut receipt["lifetime"]["native"]["details"]["execution_cgroup"];
    registration["path"] = json!(other);
    registration["device"] = json!(meta.dev());
    registration["inode"] = json!(meta.ino());
    write_json(&attempt.join("jail.json"), &receipt);

    for extra in [&["--dry-run"][..], &[][..]] {
        let (code, report, stderr) = gc(&orphan.run, extra);
        assert_eq!(code, Some(0), "{extra:?}: {stderr}\n{report:#}");
        let cgroup = text(&report, "cgroup");
        assert!(
            cgroup.starts_with("retained") && cgroup.contains("leaf's name"),
            "{extra:?}: {report:#}"
        );
        assert!(
            bystander.try_wait().unwrap().is_none(),
            "gc killed through a forged record"
        );
        assert_eq!(inode(&other), Some(meta.ino()));
        assert!(gc_actions(&attempt).is_empty());
    }
    bystander.kill().unwrap();
    bystander.wait().unwrap();
}

/// A same-uid process in a `none` leaf may make cgroups inside it. The kill
/// and the population check are recursive, so the nested descendant is
/// ended too, and the leaf is removed only after its emptied child cgroups
/// (the kernel refuses `rmdir` of a cgroup with children).
#[test]
fn j4_c03_child_cgroups_inside_an_orphan_leaf_are_ended_and_removed() {
    if !live() {
        return;
    }
    let orphan = Orphan::nested(2);
    let attempt = orphan.attempt();
    assert!(orphan.leaf.join("n0").join("n1").is_dir());
    let (code, report, stderr) = gc(&orphan.run, &[]);
    assert_eq!(code, Some(0), "{stderr}\n{report:#}");
    assert_eq!(
        text(&report, "cgroup"),
        "terminated_orphan_and_removed",
        "{report:#}"
    );
    wait_for("the nested orphan's end", || orphan.orphan_dead());
    assert_eq!(
        inode(&orphan.leaf),
        None,
        "the leaf and its children are removed"
    );
    assert_eq!(gc_actions(&attempt).len(), 3);
}

// ===========================================================================
// A contained crash leaves an empty leaf and managed scratch
// ===========================================================================

/// §9.3, §14.2: when a contained supervisor dies, the watcher ends bubblewrap
/// and the namespace dies with its init, so the leaf empties; nothing removes
/// it and the managed scratch the child wrote. `gc` identifies the leaf,
/// sees it empty, removes it, and then (tree end verified through it) removes
/// the managed scratch; the dry run first reports both and changes nothing.
#[test]
fn j4_c03_contained_crash_leaves_an_empty_leaf_that_gc_removes() {
    if !common::live() || !live() {
        return;
    }
    let jail = Jail::new().expect("a private harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).expect("the workspace");
    let mut spawned = jail
        .arg("run")
        .arg("--profile")
        .arg("tool")
        .arg("--workspace")
        .arg(&workspace)
        .receipt()
        .timeout(Duration::from_secs(60))
        .target([
            "/bin/sh",
            "-c",
            "echo left > /tmp/left-behind; exec sleep 120 </dev/null >/dev/null 2>&1",
        ])
        .spawn()
        .expect("the jail starts");
    let enforced = receipt_in_phase(&spawned, "enforced");
    let (leaf, leaf_inode) = leaf_of(&enforced);
    let _guard = LeafGuard::new(&leaf, leaf_inode);
    let attempt = attempt_of(&spawned.root().join("data"));
    let scratch = attempt.join("scratch");
    wait_for("the child's scratch file", || {
        scratch.join("left-behind").exists()
    });
    assert!(populated(&leaf));
    spawned
        .kill()
        .expect("the harness kills its own supervisor");
    let run = spawned.wait().expect("the dead supervisor is collected");
    assert_eq!(run.signal(), Some(libc::SIGKILL), "{}", run.stderr_text());
    wait_for("the contained tree to die with its supervisor", || {
        !populated(&leaf)
    });
    assert_eq!(inode(&leaf), Some(leaf_inode), "nothing removed the leaf");
    let receipt = std::fs::read(attempt.join("jail.json")).unwrap();
    assert_eq!(read_json(&attempt.join("jail.json"))["phase"], "enforced");

    let (code, report, stderr) = gc(&run, &["--dry-run"]);
    assert_eq!(code, Some(0), "{stderr}\n{report:#}");
    assert_eq!(text(&report, "cgroup"), "would_remove", "{report:#}");
    assert_eq!(text(&report, "scratch"), "would_remove", "{report:#}");
    assert_eq!(inode(&leaf), Some(leaf_inode));
    assert!(scratch.join("left-behind").is_file());

    let (code, report, stderr) = gc(&run, &[]);
    assert_eq!(code, Some(0), "{stderr}\n{report:#}");
    assert_eq!(text(&report, "cgroup"), "removed", "{report:#}");
    assert_eq!(text(&report, "scratch"), "removed", "{report:#}");
    assert_eq!(inode(&leaf), None);
    assert!(!scratch.exists());
    assert_eq!(
        gc_actions(&attempt),
        ["gc_removed_cgroup", "gc_removed_scratch"]
    );
    assert_eq!(std::fs::read(attempt.join("jail.json")).unwrap(), receipt);
}
