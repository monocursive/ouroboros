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
    gc_at(&run.data_dir, extra)
}

/// The real `gc --json` over a state root.
fn gc_at(data: &Path, extra: &[&str]) -> (Option<i32>, Value, String) {
    let output = Command::new(harness::jail_path())
        .arg("gc")
        .args(extra)
        .arg("--json")
        .env("OURO_DATA_DIR", data)
        .env("OURO_CONFIG_DIR", data.with_file_name("config"))
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
            "gc_removing_cgroup",
            "gc_removed_cgroup",
            "gc_finished"
        ]
    );
    let state = read_json(&attempt.join("jail-state.json"));
    for action in state["gc_actions"].as_array().unwrap() {
        if action["action"] == "gc_finished" {
            continue;
        }
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
        text(&report, "reason").starts_with("finished"),
        "{report:#}"
    );
    assert_eq!(gc_actions(&attempt).len(), 5, "nothing more to record");
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

/// A receipt and jail state are the supervisor's records, but in `none` the
/// same uid can rewrite them. Records that name another cgroup of this user
/// (its real path, device and inode, and a process in it) still do not name
/// an execution leaf by name, so gc never pins it, never kills through it and
/// never removes it. (J4 wave 2, N7: gc reads the leaf from jail state, so
/// both are forged, consistently; a receipt forged alone disagrees with jail
/// state, and records that disagree are retained.)
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

    // The receipt alone: it disagrees with jail state.
    let (code, report, stderr) = gc(&orphan.run, &["--dry-run"]);
    assert_eq!(code, Some(0), "{stderr}\n{report:#}");
    let cgroup = text(&report, "cgroup");
    assert!(
        cgroup.starts_with("retained") && cgroup.contains("different"),
        "{report:#}"
    );
    assert!(bystander.try_wait().unwrap().is_none());

    // Both records, consistently.
    let mut state = read_json(&attempt.join("jail-state.json"));
    state["execution_cgroup"] = json!({"path": other, "device": meta.dev(), "inode": meta.ino()});
    write_json(&attempt.join("jail-state.json"), &state);

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
    assert_eq!(gc_actions(&attempt).len(), 5, "{:?}", gc_actions(&attempt));
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
        [
            "gc_removing_cgroup",
            "gc_removed_cgroup",
            "gc_removed_scratch",
            "gc_finished"
        ]
    );
    assert_eq!(std::fs::read(attempt.join("jail.json")).unwrap(), receipt);
}

// ===========================================================================
// N7: the execution leaf is registered in jail state before it exists
// ===========================================================================

/// The execution leaves (`ouro-*.leaf`) directly under this user's delegated
/// subtree, by name, with their inodes.
fn leaves(root: &Path) -> Vec<(String, u64)> {
    let mut found: Vec<(String, u64)> = std::fs::read_dir(root)
        .map(|listing| {
            listing
                .flatten()
                .filter_map(|entry| {
                    let name = entry.file_name().to_str()?.to_owned();
                    (name.starts_with("ouro-") && name.ends_with(".leaf"))
                        .then(|| Some((name, entry.metadata().ok()?.ino())))?
                })
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

/// One `tool` attempt aborted by `OURO_JAIL_TEST_ABORT_AT=<point>` (S9),
/// exactly as `j4_records_linux` crashes one: no core file, the release
/// binary, the harness's own private state root.
fn crashed_tool_run(point: &str) -> Run {
    let jail = Jail::with_program("/bin/sh")
        .expect("harness")
        .args(["-c", "ulimit -c 0 && exec \"$0\" \"$@\""])
        .arg(harness::jail_path());
    let workspace = jail.root().join("workspace");
    std::fs::create_dir_all(&workspace).expect("the workspace");
    jail.arg("run")
        .args(["--profile", "tool", "--workspace"])
        .arg(&workspace)
        .env(ouro_jail::state::ABORT_AT_SEAM, point)
        .receipt()
        .timeout(Duration::from_secs(60))
        .target(["/bin/true"])
        .run()
        .expect("the run")
}

/// N7 (J4 wave 2). The execution leaf used to be created (and, in the
/// contained profiles, populated with the blocked backend) before anything
/// named it outside a receipt, so a supervisor that died between `mkdir` and
/// its `prepared` receipt left a leaf `gc` could never find. Its name is now
/// in jail state before `mkdir` (P15) and its device and inode right after
/// (P16), before anything is placed in it, and `gc` reads the leaf from jail
/// state. A crash at each of those writes, at the boundary registration (P4)
/// and at the `prepared` receipt (P5) leaves either no leaf at all or one
/// that jail state names and that `gc` removes: after the name alone, the
/// leaf is empty and is removed by name; after the identity, it is the
/// positively identified leaf (the lifetime watcher ended its tree when the
/// supervisor died).
#[test]
fn j4_n7_a_crash_between_mkdir_and_the_receipt_leaves_a_leaf_gc_removes() {
    if !common::live() || !live() {
        return;
    }
    // SAFETY: geteuid takes no arguments and cannot fail.
    let root = ouro_jail::platform::linux::cgroup::delegated_root(unsafe { libc::geteuid() })
        .expect("a delegated subtree (checked by live())");
    // (abort point, whether a leaf exists once the supervisor is dead,
    // whether jail state holds its identity or only its name)
    let cases = [
        ("execution_leaf:dir_synced", false, false),
        ("execution_leaf_identity:temp_written", true, false),
        ("execution_leaf_identity:temp_synced", true, false),
        ("execution_leaf_identity:dir_synced", true, true),
        ("boundary:temp_written", true, true),
        ("prepared_receipt:temp_written", true, true),
    ];
    let mut problems = Vec::new();
    for (point, exists, with_identity) in cases {
        let before = leaves(&root);
        let run = crashed_tool_run(point);
        if run.signal() != Some(libc::SIGABRT) {
            problems.push(format!(
                "{point}: the abort point was never reached (exit {:?}): {}",
                run.code(),
                run.stderr_text().trim()
            ));
            continue;
        }
        let appeared: Vec<(String, u64)> = leaves(&root)
            .into_iter()
            .filter(|leaf| !before.contains(leaf))
            .collect();
        let attempt = attempt_of(&run.data_dir);
        let state = read_json(&attempt.join("jail-state.json"));
        let registered = &state["execution_cgroup"];
        let Some(path) = registered["path"].as_str().map(PathBuf::from) else {
            problems.push(format!(
                "{point}: jail state registers no execution leaf ({registered}); leaves that \
                 appeared during the run: {appeared:?}"
            ));
            continue;
        };
        let _guard = inode(&path).map(|now| LeafGuard::new(&path, now));
        if path.parent() != Some(root.as_path()) {
            problems.push(format!(
                "{point}: {} is not under {}",
                path.display(),
                root.display()
            ));
            continue;
        }
        let identified = registered["inode"].as_u64();
        if identified.is_some() != with_identity {
            problems.push(format!(
                "{point}: the registration is {registered}, a crash here leaves identity={with_identity}"
            ));
        }
        if inode(&path).is_some() != exists {
            problems.push(format!(
                "{point}: leaf present={}, a crash here leaves {exists}",
                inode(&path).is_some()
            ));
            continue;
        }
        if let (Some(recorded), Some(now)) = (identified, inode(&path))
            && recorded != now
        {
            problems.push(format!("{point}: registered inode {recorded}, found {now}"));
        }
        if exists {
            wait_for("the dead supervisor's leaf to empty", || !populated(&path));
        }
        let (code, report, stderr) = gc(&run, &[]);
        if code != Some(0) {
            problems.push(format!("{point}: gc exited {code:?}: {stderr}\n{report:#}"));
        }
        if inode(&path).is_some() {
            problems.push(format!(
                "{point}: gc left the registered leaf {}: {report:#}",
                path.display()
            ));
        }
        let actions = gc_actions(&attempt);
        if exists != actions.iter().any(|action| action == "gc_removed_cgroup") {
            problems.push(format!("{point}: gc recorded {actions:?}: {report:#}"));
        }
        eprintln!(
            "{point}: cgroup {:?}, recorded {actions:?}",
            text(&report, "cgroup")
        );
    }
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// A persistence seam that fails the first write at one site with ENOSPC
/// and keeps the bytes it was asked to write.
struct FailAt {
    site: ouro_jail::state::Site,
    asked: std::sync::Mutex<Option<Vec<u8>>>,
}

impl ouro_jail::state::PersistIo for FailAt {
    fn write(
        &self,
        site: ouro_jail::state::Site,
        file: &mut std::fs::File,
        bytes: &[u8],
    ) -> std::io::Result<usize> {
        if site == self.site {
            let mut asked = self.asked.lock().unwrap();
            if asked.is_none() {
                *asked = Some(bytes.to_vec());
                return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
            }
        }
        std::io::Write::write(file, bytes)
    }
}

/// N7, a failed registration (in process, through the persistence seam, on
/// the `none` boundary, which needs its leaf whatever the policy asks): a
/// failed name (P15) refuses `state_write_failed` before `mkdir`, so the leaf
/// it would have made never exists; a failed identity (P16) refuses too and
/// removes the empty leaf it made, and jail state names it by name only, so
/// even a failed removal would leave it findable. Nothing is launched.
#[test]
fn j4_n7_a_failed_leaf_registration_refuses_and_leaves_no_leaf() {
    use ouro_jail::platform::{PlanRequest, PreparedPlan, Sinks};
    use ouro_jail::policy::{ProfileName, ResolveInputs, ScratchRoot};
    use ouro_jail::records::{ErrorCode, Os};
    use ouro_jail::state::Site;
    if !live() {
        return;
    }
    for site in [Site::ExecutionLeaf, Site::ExecutionLeafIdentity] {
        let label = site.as_str();
        let root = common::private_tempdir();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let attempt_id = ouro_jail::state::AttemptId::generate();
        // J4 wave 3 (G2): an attempt root is named by its attempt id, and
        // the leaf carries it.
        let attempt = root.path().join(attempt_id.as_str());
        std::fs::create_dir(&attempt).unwrap();
        write_json(
            &attempt.join("jail-state.json"),
            &json!({
                "schema": "ouro.jail.state/1",
                "attempt_id": attempt_id.as_str(),
                "execution_cgroup": null,
            }),
        );
        let resolved = ouro_jail::policy::resolve(&ResolveInputs {
            platform: Os::Linux,
            base_profile: ProfileName::None,
            policy_name: "none".to_owned(),
            baseline: ouro_jail::profiles::baseline(ProfileName::None, Os::Linux, &|_| None),
            workspace: workspace.as_os_str().as_encoded_bytes().to_vec(),
            scratch: ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        })
        .expect("the bare none baseline resolves");
        let plan = PreparedPlan {
            attempt_id: attempt_id.as_str().to_owned(),
            attempt_dir: attempt.clone(),
            request: PlanRequest {
                requirements: ouro_jail::capability::requirements(&resolved.snapshot),
                snapshot: resolved.snapshot,
                profile: ProfileName::None,
            },
            argv: vec![b"/bin/true".to_vec()],
            workspace,
            launch: None,
            proxy: None,
        };
        let seam = std::sync::Arc::new(FailAt {
            site,
            asked: std::sync::Mutex::new(None),
        });
        let deadline = ouro_jail::platform::linux::clock::Deadline::after(Duration::from_secs(10));
        let result = ouro_jail::state::with_persist_io(seam.clone(), || {
            ouro_jail::platform::linux::uncontained::prepare(plan, Sinks { trace: None }, deadline)
        });
        let Err(error) = result else {
            panic!("{label}: the boundary was prepared although its leaf was not registered");
        };
        assert_eq!(error.code, ErrorCode::StateWriteFailed, "{label}: {error}");
        let asked: Value =
            serde_json::from_slice(&seam.asked.lock().unwrap().clone().expect("the write"))
                .unwrap();
        let path = PathBuf::from(asked["execution_cgroup"]["path"].as_str().unwrap());
        assert_eq!(
            path.file_name().unwrap().to_str(),
            Some(ouro_jail::gc::leaf_name_of(attempt_id.as_str()).as_str()),
            "{label}: {}",
            path.display()
        );
        assert_eq!(
            inode(&path),
            None,
            "{label}: {} was left behind",
            path.display()
        );
        let state = read_json(&attempt.join("jail-state.json"));
        let expected = if site == Site::ExecutionLeaf {
            Value::Null
        } else {
            json!({"path": path, "device": null, "inode": null})
        };
        assert_eq!(state["execution_cgroup"], expected, "{label}");
    }
}

// ===========================================================================
// J4 wave 3: the gc review's findings, live (each red on 191bdb7b first)
// ===========================================================================

/// The attempt id of the only attempt under a run's state root.
fn attempt_id_of(attempt: &Path) -> String {
    attempt.file_name().unwrap().to_str().unwrap().to_owned()
}

/// Whether the process with this pid exists and is not a zombie.
fn running(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|raw| identity::parse_state(&raw).ok())
        .is_some_and(|state| state != 'Z' && state != 'X')
}

/// G2 (gc review): the execution leaf carries its attempt. Both call sites
/// (the contained platform and `none`) register and create
/// `ouro-<attempt id>.leaf`, and the receipt names the same leaf.
#[test]
fn j4_w3_g2_each_execution_leaf_is_named_for_its_attempt() {
    if !live() {
        return;
    }
    let mut profiles = vec!["none"];
    if common::live() {
        profiles.push("tool");
    }
    for profile in profiles {
        let jail = Jail::new().expect("a private harness");
        let workspace = jail.root().join("workspace");
        std::fs::create_dir(&workspace).expect("the workspace");
        let mut jail = jail
            .arg("run")
            .args(["--profile", profile])
            .arg("--workspace")
            .arg(&workspace);
        if profile == "none" {
            jail = jail.args(["--observe", "off"]);
        }
        let run = jail
            .receipt()
            .timeout(Duration::from_secs(60))
            .target(["/bin/true"])
            .run()
            .expect("the run");
        assert_eq!(run.code(), Some(0), "{profile}: {}", run.stderr_text());
        let attempt = attempt_of(&run.data_dir);
        let id = attempt_id_of(&attempt);
        let state = read_json(&attempt.join("jail-state.json"));
        let path = PathBuf::from(
            state["execution_cgroup"]["path"]
                .as_str()
                .unwrap_or_else(|| panic!("{profile}: no leaf registered: {state:#}")),
        );
        assert_eq!(
            path.file_name().unwrap().to_str(),
            Some(format!("ouro-{id}.leaf").as_str()),
            "{profile}: the registered leaf does not carry its attempt"
        );
        let receipt = read_json(&attempt.join("jail.json"));
        assert_eq!(
            receipt["lifetime"]["native"]["details"]["execution_cgroup"]["path"],
            json!(path),
            "{profile}"
        );
    }
}

/// G2 (gc review, SAFETY, C03; reproduced live on 17a0533c). Attempt A's
/// jail state, as a same-uid `none` child can write it, registers ANOTHER,
/// live attempt B's execution leaf with its real path, device and inode. gc,
/// run on the dead attempt A, pinned B's leaf (right name shape, place,
/// device, inode) and killed B's tree while B's supervisor was alive and
/// held its own lease. Now the leaf is not A's (its name carries B), so gc
/// retains and reports it; B's run ends on its own, untouched.
#[test]
fn j4_w3_g2_a_forged_registration_of_a_live_attempts_leaf_is_never_acted_on() {
    if !live() {
        return;
    }
    let jail = Jail::new().expect("a private harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).expect("the workspace");
    let data = jail.data_dir();
    let mut spawned = jail
        .arg("run")
        .args(["--profile", "none", "--observe", "off", "--workspace"])
        .arg(&workspace)
        .receipt()
        .timeout(Duration::from_secs(90))
        .target(["/bin/sleep", "30"])
        .spawn()
        .expect("attempt B starts");
    let enforced = receipt_in_phase(&spawned, "enforced");
    let (leaf, leaf_inode) = leaf_of(&enforced);
    let _guard = LeafGuard::new(&leaf, leaf_inode);
    wait_for("B's leaf to be populated", || populated(&leaf));
    let b = attempt_of(&data);
    let b_state = read_json(&b.join("jail-state.json"));
    let supervisor = spawned.pid() as i32;

    // A: a claimed attempt whose owner is dead, registering B's leaf.
    let a_id = ouro_jail::state::AttemptId::generate();
    let a = data.join("attempts").join(a_id.as_str());
    std::fs::create_dir(&a).unwrap();
    std::fs::set_permissions(&a, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    std::fs::write(a.join("jail.lock"), b"").unwrap();
    std::fs::set_permissions(
        a.join("jail.lock"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let dead = {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    };
    write_json(
        &a.join("jail-state.json"),
        &json!({
            "schema": "ouro.jail.state/1",
            "attempt_id": a_id.as_str(),
            "os": b_state["os"],
            "arch": b_state["arch"],
            "owner": {"pid": dead, "boot_id": identity::boot_id().unwrap(), "start_time_ticks": 1},
            "execution_cgroup": b_state["execution_cgroup"],
        }),
    );

    let mut problems = Vec::new();
    for extra in [&["--dry-run"][..], &[][..]] {
        let (code, report, stderr) = gc_at(&data, extra);
        let entry = report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["attempt_id"] == a_id.as_str())
            .cloned()
            .unwrap_or(Value::Null);
        if code != Some(0) {
            problems.push(format!("{extra:?}: gc exited {code:?}: {stderr}"));
        }
        let cgroup = entry["cgroup"].as_str().unwrap_or_default();
        if !(cgroup.starts_with("retained") && cgroup.contains("not this attempt's")) {
            problems.push(format!("{extra:?}: A's entry: {entry:#}"));
        }
        if !running(supervisor) {
            problems.push(format!("{extra:?}: B's supervisor died"));
        }
        if inode(&leaf) != Some(leaf_inode) {
            problems.push(format!("{extra:?}: B's leaf was removed"));
        } else if !populated(&leaf) {
            problems.push(format!("{extra:?}: B's tree was killed"));
        }
        if !gc_actions(&a).is_empty() {
            problems.push(format!("{extra:?}: A recorded {:?}", gc_actions(&a)));
        }
    }
    spawned
        .kill()
        .expect("the harness kills its own supervisor");
    let run = spawned.wait();
    assert!(
        problems.is_empty(),
        "{}\nB: {:?}",
        problems.join("\n"),
        run.map(|run| (run.code(), run.signal(), run.stderr_text()))
    );
}

/// G1 (gc review, HONESTY; reproduced live on 17a0533c). A `tool` run with
/// vendor state whose supervisor is SIGKILLed after release leaves an
/// `enforced` receipt. gc verifies the leaf empty itself, which permits the
/// vendor-state cleanup; the resumption then rewrote the `enforced` receipt
/// with `state_cleanup = complete` at the next revision, which the schema
/// rejects. Now gc completes the cleanup, records it in jail state and its
/// report, and leaves the receipt byte for byte.
#[test]
fn j4_w3_g1_gc_never_rewrites_a_dead_supervisors_enforced_receipt() {
    if !common::live() || !live() {
        return;
    }
    let jail = Jail::new().expect("a private harness");
    let launch = jail.config_dir().join("launch");
    std::fs::create_dir(&launch).unwrap();
    std::fs::set_permissions(&launch, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    std::fs::write(
        launch.join("fixture.toml"),
        "name = \"fixture\"\njail = \"tool\"\nstate_var = \"FIX_HOME\"\n",
    )
    .unwrap();
    std::fs::set_permissions(
        launch.join("fixture.toml"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).expect("the workspace");
    let data = jail.data_dir();
    let mut spawned = jail
        .arg("run")
        .args(["--launch", "fixture", "--workspace"])
        .arg(&workspace)
        .receipt()
        .timeout(Duration::from_secs(60))
        .target(["/bin/sleep", "60"])
        .spawn()
        .expect("the jail starts");
    let enforced = receipt_in_phase(&spawned, "enforced");
    let (leaf, leaf_inode) = leaf_of(&enforced);
    let _guard = LeafGuard::new(&leaf, leaf_inode);
    let attempt = attempt_of(&data);
    let vendor = attempt.join("vendor-state");
    assert!(vendor.is_dir(), "the launch profile made vendor state");
    spawned
        .kill()
        .expect("the harness kills its own supervisor");
    let run = spawned.wait().expect("the dead supervisor is collected");
    assert_eq!(run.signal(), Some(libc::SIGKILL), "{}", run.stderr_text());
    wait_for("the contained tree to die with its supervisor", || {
        !populated(&leaf)
    });
    let before = std::fs::read(attempt.join("jail.json")).unwrap();
    let receipt: Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(receipt["phase"], "enforced");
    common::check_receipt(&receipt).expect("the supervisor's last receipt is valid");

    let (code, report, stderr) = gc(&run, &[]);
    assert_eq!(code, Some(0), "{stderr}\n{report:#}");
    assert!(
        !vendor.exists(),
        "gc's verified end permits the cleanup: {report:#}"
    );
    assert_eq!(
        read_json(&attempt.join("jail-state.json"))["state_cleanup"],
        "complete"
    );
    let after = std::fs::read(attempt.join("jail.json")).unwrap();
    let value: Value = serde_json::from_slice(&after).unwrap();
    assert!(
        common::check_receipt(&value).is_ok(),
        "gc left a schema-invalid receipt: {:?}",
        common::check_receipt(&value)
    );
    assert_eq!(
        after, before,
        "S6: gc rewrote the supervisor's enforced receipt"
    );
    assert!(text(&report, "reason").contains("jail state"), "{report:#}");
}

/// P1 (c) (records review, HONESTY/SAFETY). A thread stuck in a D-state
/// `fsync` or `rename` keeps the thread-group leader a zombie (`Z`) while
/// the thread may still write, and gc took a zombie for a dead owner, so it
/// could remove a temporary file the living thread was about to rename (or
/// act on the leaf while it still wrote). A zombie leader whose thread group
/// still has another thread is alive. The helper below makes one: its
/// leader thread exits, one thread lives on.
#[test]
fn j4_w3_p1c_a_zombie_leader_with_a_live_thread_is_alive() {
    let tmp = common::private_tempdir();
    let ready = tmp.path().join("ready");
    let mut helper = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "j4_w3_zombie_leader_helper",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("OURO_W3G_ZOMBIE_READY", &ready)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let pid = helper.id() as i32;
    let state = || {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|raw| identity::parse_state(&raw).ok())
    };
    wait_for("the helper's leader to exit alone", || {
        ready.exists() && state() == Some('Z')
    });
    let threads = std::fs::read_dir(format!("/proc/{pid}/task"))
        .unwrap()
        .count();
    assert!(threads >= 2, "{threads} task(s)");
    let owner = ouro_jail::gc::OwnerRecord {
        pid: pid as u32,
        boot_id: identity::boot_id().unwrap(),
        start_time_ticks: identity::start_time_ticks(pid).unwrap(),
    };
    let liveness = ouro_jail::platform::linux::reconcile::owner_liveness(&owner);

    // Through the product: an attempt this zombie owns, with a temporary
    // file a living thread may still rename, is retained whole.
    let data = tmp.path().join("data");
    let id = ouro_jail::state::AttemptId::generate();
    let root = data.join("attempts").join(id.as_str());
    std::fs::create_dir_all(&root).unwrap();
    for dir in [&data, &data.join("attempts"), &root] {
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    }
    std::fs::write(root.join("jail.lock"), b"").unwrap();
    std::fs::set_permissions(
        root.join("jail.lock"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    write_json(
        &root.join("jail-state.json"),
        &json!({
            "schema": "ouro.jail.state/1",
            "attempt_id": id.as_str(),
            "os": "linux",
            "arch": std::env::consts::ARCH,
            "owner": {"pid": owner.pid, "boot_id": owner.boot_id, "start_time_ticks": owner.start_time_ticks},
        }),
    );
    let temp = root.join(format!(
        ".jail.json.{}.tmp",
        ouro_jail::state::AttemptId::generate()
            .as_str()
            .trim_start_matches("att_")
    ));
    std::fs::write(&temp, b"{\"partial\": ").unwrap();
    let output = Command::new(harness::jail_path())
        .args(["gc", "--json"])
        .env("OURO_DATA_DIR", &data)
        .env("OURO_CONFIG_DIR", tmp.path().join("config"))
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    let temp_kept = temp.exists();
    // SAFETY: the helper is this test's own unreaped child; SIGKILL to its
    // pid ends its whole thread group.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let _ = helper.wait();

    assert_eq!(
        liveness,
        ouro_jail::gc::Liveness::Alive,
        "a zombie leader with {threads} tasks"
    );
    assert_eq!(report["entries"][0]["action"], "retained", "{report:#}");
    assert!(
        report["entries"][0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("alive")),
        "{report:#}"
    );
    assert!(
        temp_kept,
        "gc removed a temporary file a living thread may rename: {report:#}"
    );
}

/// The helper of [`j4_w3_p1c_a_zombie_leader_with_a_live_thread_is_alive`]:
/// the thread-group leader exits alone (`exit`, not `exit_group`) and one
/// thread lives on, as a thread in a long D-state `fsync` does.
#[test]
#[ignore = "a helper process of j4_w3_p1c_a_zombie_leader_with_a_live_thread_is_alive"]
fn j4_w3_zombie_leader_helper() {
    extern "C" fn leave(_: libc::c_int) {
        // SAFETY: exit(2) of the calling thread only; async-signal-safe.
        unsafe { libc::syscall(libc::SYS_exit, 0) };
    }
    let Some(ready) = std::env::var_os("OURO_W3G_ZOMBIE_READY") else {
        return;
    };
    // SAFETY: getpid and gettid take no arguments and cannot fail.
    let (pid, tid) = unsafe { (libc::getpid(), libc::gettid()) };
    if tid == pid {
        std::thread::spawn(move || {
            std::fs::write(&ready, pid.to_string()).unwrap();
            std::thread::sleep(Duration::from_secs(60));
        });
        std::thread::sleep(Duration::from_millis(50));
        // SAFETY: exit(2) of this (leader) thread only.
        unsafe { libc::syscall(libc::SYS_exit, 0) };
    } else {
        // SAFETY: a zeroed sigaction with a plain handler is valid; the
        // handler only calls exit(2) of the thread it interrupts, and
        // tgkill targets the leader thread of this very process.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = leave as *const () as usize;
            libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut());
            libc::syscall(libc::SYS_tgkill, pid, pid, libc::SIGUSR1);
        }
        std::fs::write(&ready, pid.to_string()).unwrap();
        std::thread::sleep(Duration::from_secs(60));
    }
}
