//! J5-C, R02.3 and R02.4: the persistence sites the J4 crash and fault
//! matrices never reached (jail-v1 §7, §13.2, §14.2; R02).
//!
//! R02.3, live: the release binary is aborted by
//! `OURO_JAIL_TEST_ABORT_AT=<site>:<point>[:<n>]` (S9; the ordinal is J5-C's,
//! `state::persist::parse_abort_at`) at each named point of
//!
//! - P7, the receipt recording a detected lifetime-integrity loss, written
//!   while a `none` target that moved itself out of its leaf still runs;
//! - P12, gc resuming a vendor-state cleanup the supervisor left pending:
//!   both of its writes, the receipt it completes (its first replacement at
//!   the site) and then jail state (its second);
//! - P13, gc's record of a dead `agent` attempt's proxy directory;
//! - P14, each of gc's records in the order one pass writes them, over a
//!   dead `none` supervisor's leaf a descendant still populates
//!   (`gc_terminating_orphan`, `gc_terminated_orphan`, `gc_removing_cgroup`,
//!   `gc_removed_cgroup`, ..., `gc_finished`) and over a dead `tool`
//!   supervisor's empty leaf and managed scratch (`gc_removing_cgroup`,
//!   `gc_removed_cgroup`, `gc_removed_scratch`, `gc_finished`). The J4
//!   matrix crashed only the first.
//!
//! After each crash every record present parses, `jail.json` passes the
//! frozen contract, the replaced record shows the prior content before the
//! rename and the new one after it, what the site does before or after its
//! record (a kill, an `rmdir`, a removal) is where the record says, the
//! temporary files left are exactly the crashed replacement's (the explicit
//! incomplete state, `state::leftover_temp_files`), and the next gc pass
//! finishes with every record kept.
//!
//! R02.4, simulated: disk-full, short-write, fsync, rename and
//! directory-sync faults at P15 and P16, the execution leaf's name (before
//! `mkdir`) and identity (after it), injected through the persistence seam
//! into the real leaf creation (`ExecutionCgroup::create_for_attempt`) in
//! this process, against a real attempt the release binary left and a real
//! delegated cgroup. Those two sites are reached only by the Linux platform,
//! which the portable matrix (R02.2) cannot run.
//!
//! Needs `OURO_CONFORMANCE=1` and the reference host. Every process these
//! tests signal is their own jail's supervisor, by the pidfd of the process
//! the harness spawned; every cgroup they touch is one their own attempt
//! registered (checked by inode) or one they made.

#![cfg(target_os = "linux")]

use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ouro_fixture::harness::{self, Jail, Run};
use ouro_jail::platform::linux::cgroup::{self, ExecutionCgroup};
use ouro_jail::platform::linux::identity;
use ouro_jail::policy::LimitsSnapshot;
use ouro_jail::records::ErrorCode;
use ouro_jail::state::{self, AttemptDir, AttemptId, PersistIo, Site};
use serde_json::Value;

mod common;

const PYTHON: &str = "/usr/bin/python3";

/// A crash point and what the records must show after it.
#[derive(Clone, Copy, Debug)]
struct Point {
    name: &'static str,
    /// The new content is visible under the target name.
    published: bool,
    /// The temporary name is still there.
    temp_left: bool,
}

const POINTS: [Point; 4] = [
    Point {
        name: "temp_written",
        published: false,
        temp_left: true,
    },
    Point {
        name: "temp_synced",
        published: false,
        temp_left: true,
    },
    Point {
        name: "renamed",
        published: true,
        temp_left: false,
    },
    Point {
        name: "dir_synced",
        published: true,
        temp_left: false,
    },
];

fn live() -> bool {
    if !common::live() {
        return false;
    }
    let leaf = ouro_jail::platform::linux::probe::run_one(
        "cgroup_delegated_leaf",
        &harness::jail_path(),
        Path::new("bwrap"),
    );
    if leaf.status != ouro_jail::platform::linux::probe::ProbeStatus::Available {
        harness::skip_or_fail(&format!(
            "these crashes need a delegated user scope: {}",
            leaf.evidence
        ));
        return false;
    }
    if !Path::new(PYTHON).is_file() {
        harness::skip_or_fail("the none fixtures are python3 scripts");
        return false;
    }
    true
}

fn parse(path: &Path) -> Result<Option<Value>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("{} does not parse: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{} cannot be read: {error}", path.display())),
    }
}

fn read_json(path: &Path) -> Value {
    parse(path)
        .unwrap_or_else(|problem| panic!("{problem}"))
        .unwrap_or_else(|| panic!("{} is missing", path.display()))
}

fn signal_of(status: std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal()
}

/// A jail whose abort leaves no core file: `ulimit -c 0`, then exec the jail
/// itself, so the harness's channels reach it unchanged.
fn aborting_jail() -> Jail {
    Jail::with_program("/bin/sh")
        .expect("a private harness")
        .args(["-c", "ulimit -c 0 && exec \"$0\" \"$@\""])
        .arg(harness::jail_path())
}

fn private_workspace(jail: &Jail) -> PathBuf {
    let workspace = jail.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
    workspace
}

/// The one attempt under `data`.
fn the_attempt(data: &Path) -> Result<PathBuf, String> {
    let attempts: Vec<PathBuf> = std::fs::read_dir(data.join("attempts"))
        .map(|listing| listing.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    match attempts.as_slice() {
        [dir] => Ok(dir.clone()),
        other => Err(format!("expected one attempt, found {other:?}")),
    }
}

fn attempt_of(data: &Path, dir: &Path) -> AttemptDir {
    let name = dir.file_name().unwrap().to_string_lossy().into_owned();
    AttemptDir::new(data, &AttemptId::parse(&name).expect("an attempt id"))
}

fn leftover(data: &Path, dir: &Path) -> Vec<String> {
    state::leftover_temp_files(&attempt_of(data, dir)).expect("the attempt lists")
}

/// Whether the temporary files are exactly the crashed replacement's: one of
/// `.<record>.*.tmp` before its rename, none after, and nothing else.
fn temps_match(leftover: &[String], record: &str, point: Point) -> bool {
    let ours = leftover
        .iter()
        .filter(|temp| temp.starts_with(&format!(".{record}.")))
        .count();
    ours == usize::from(point.temp_left) && leftover.len() == ours
}

/// The real `gc --json` over `data`, aborting at `seam` when given.
fn gc_run(data: &Path, seam: Option<&str>) -> Output {
    let mut command = std::process::Command::new("/bin/sh");
    command
        .args(["-c", "ulimit -c 0 && exec \"$0\" \"$@\""])
        .arg(harness::jail_path())
        .args(["gc", "--json"])
        .env("OURO_DATA_DIR", data)
        .env("OURO_CONFIG_DIR", data.with_file_name("config"))
        .env_remove(state::ABORT_AT_SEAM);
    if let Some(seam) = seam {
        command.env(state::ABORT_AT_SEAM, seam);
    }
    command.output().expect("gc runs")
}

/// A gc pass that must abort at `seam`.
fn gc_crash(label: &str, data: &Path, seam: &str, problems: &mut Vec<String>) -> bool {
    let crashed = gc_run(data, Some(seam));
    if signal_of(crashed.status) == Some(libc::SIGABRT) {
        return true;
    }
    problems.push(format!(
        "{label}: gc was not aborted at {seam} (status {:?}): the point was never reached: {}",
        crashed.status,
        String::from_utf8_lossy(&crashed.stderr).trim()
    ));
    false
}

/// A gc pass without the seam that must finish (§6.4: exit 0).
fn gc_finishes(label: &str, data: &Path, problems: &mut Vec<String>) -> Value {
    let again = gc_run(data, None);
    let report = serde_json::from_slice::<Value>(&again.stdout).unwrap_or(Value::Null);
    if !again.status.success() || report.is_null() {
        problems.push(format!(
            "{label}: the next gc did not finish ({:?}): {}{}",
            again.status,
            String::from_utf8_lossy(&again.stdout),
            String::from_utf8_lossy(&again.stderr)
        ));
    }
    report
}

/// Every record present parses and the receipt passes the frozen contract.
fn records_valid(label: &str, dir: &Path, problems: &mut Vec<String>) {
    for name in ["jail-state.json", "policy.json", "jail.json"] {
        match parse(&dir.join(name)) {
            Ok(Some(value)) if name == "jail.json" => {
                if let Err(error) = common::check_receipt(&value) {
                    problems.push(format!("{label}: jail.json fails the contract: {error}"));
                }
            }
            Ok(_) => {}
            Err(problem) => problems.push(format!("{label}: {problem}")),
        }
    }
}

/// The records present now, to show that a later gc keeps them.
fn present(dir: &Path) -> Vec<&'static str> {
    [
        "jail-state.json",
        "policy.json",
        "jail.json",
        "trace.ndjson",
    ]
    .into_iter()
    .filter(|name| dir.join(name).exists())
    .collect()
}

fn kept(label: &str, dir: &Path, before: &[&str], problems: &mut Vec<String>) {
    for name in before {
        if !dir.join(name).exists() {
            problems.push(format!("{label}: gc removed {name}"));
        }
    }
    records_valid(&format!("{label} after gc"), dir, problems);
}

fn populated(cgroup: &Path) -> bool {
    std::fs::read_to_string(cgroup.join("cgroup.events"))
        .is_ok_and(|events| events.lines().any(|line| line == "populated 1"))
}

fn inode(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|meta| meta.ino())
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready() {
        if Instant::now() >= deadline {
            eprintln!("timed out waiting for {what}");
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

/// The attempt's registered leaf (path and pinned inode), from jail state.
fn registered_leaf(dir: &Path) -> Option<(PathBuf, Option<u64>)> {
    let state = parse(&dir.join("jail-state.json")).ok()??;
    let leaf = &state["execution_cgroup"];
    Some((
        PathBuf::from(leaf["path"].as_str()?),
        leaf["inode"].as_u64(),
    ))
}

/// Ends and removes the leaf this test's own attempt registered, when it is
/// still that leaf (its pinned inode), whatever the test concluded: never
/// anything else.
struct LeafGuard {
    path: PathBuf,
    inode: u64,
}

impl LeafGuard {
    fn of(dir: &Path) -> Option<LeafGuard> {
        let (path, pinned) = registered_leaf(dir)?;
        let inode = pinned.or_else(|| inode(&path))?;
        Some(LeafGuard { path, inode })
    }
}

impl Drop for LeafGuard {
    fn drop(&mut self) {
        if inode(&self.path) != Some(self.inode) {
            return;
        }
        if populated(&self.path) {
            let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
            wait_for("the leaf to empty", || !populated(&self.path));
        }
        let _ = std::fs::remove_dir(&self.path);
    }
}

/// A cgroup the test creates beside the attempt leaves, the kind an
/// uncontained child can create for itself and move into.
struct Destination {
    path: PathBuf,
}

impl Destination {
    fn new(tag: &str) -> Destination {
        // SAFETY: getuid takes no arguments and cannot fail.
        let root = cgroup::delegated_root(unsafe { libc::getuid() })
            .expect("the delegated subtree exists");
        let path = root.join(format!("ouro-j5c-{tag}-{}", std::process::id()));
        std::fs::create_dir(&path).expect("a destination cgroup");
        Destination { path }
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        // Only the attempt's own target can be here: the test made this cgroup.
        if populated(&self.path) {
            let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
            wait_for("the destination to empty", || !populated(&self.path));
        }
        let _ = std::fs::remove_dir(&self.path);
    }
}

fn assert_no_problems(problems: &[String]) {
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

// ===========================================================================
// P7: the integrity receipt
// ===========================================================================

/// One crash at `point` of the receipt that records a detected integrity
/// loss (§9.3, P7). The `none` target sleeps briefly (so its exec is
/// confirmed first), moves itself into a cgroup of its own and stays alive;
/// the supervisor sees the escape and replaces `enforced`/`verified` with
/// `enforced`/`lost`, and is aborted at `point` of that replacement.
fn integrity_crash(point: Point) -> Vec<String> {
    let label = format!("integrity_receipt:{}", point.name);
    let mut problems = Vec::new();
    let destination = Destination::new(&format!("p7-{}", point.name));
    let jail = aborting_jail();
    let workspace = private_workspace(&jail);
    let data = jail.data_dir();
    let moved = jail.root().join("moved");
    let code = format!(
        "import os, time\n\
         null = os.open('/dev/null', os.O_RDWR)\n\
         for fd in (0, 1, 2): os.dup2(null, fd)\n\
         time.sleep(0.3)\n\
         open({dest:?}, 'w').write('0')\n\
         open({moved:?}, 'w').write(str(os.getpid()))\n\
         time.sleep(30)\n\
         os._exit(0)\n",
        dest = destination.path.join("cgroup.procs").to_str().unwrap(),
        moved = moved.to_str().unwrap(),
    );
    let run = jail
        .arg("run")
        .args(["--profile", "none", "--observe", "off", "--workspace"])
        .arg(&workspace)
        .env(state::ABORT_AT_SEAM, &label)
        .control()
        .receipt()
        .target([PYTHON, "-c", &code])
        .run()
        .expect("the run");
    if run.signal() != Some(libc::SIGABRT) {
        problems.push(format!(
            "{label}: the abort point was never reached (exit {:?}, signal {:?}): {}",
            run.code(),
            run.signal(),
            run.stderr_text().trim()
        ));
        return problems;
    }
    let dir = match the_attempt(&data) {
        Ok(dir) => dir,
        Err(problem) => {
            problems.push(format!("{label}: {problem}"));
            return problems;
        }
    };
    let _leaf = LeafGuard::of(&dir);
    if !moved.exists() {
        problems.push(format!("{label}: the target never moved"));
    }
    records_valid(&label, &dir, &mut problems);
    match parse(&dir.join("jail.json")) {
        Ok(Some(receipt)) => {
            let integrity = receipt["lifetime"]["integrity"].as_str().unwrap_or("-");
            let want = if point.published { "lost" } else { "verified" };
            if integrity != want || receipt["phase"] != "enforced" {
                problems.push(format!(
                    "{label}: jail.json is {} with integrity {integrity}; a crash here leaves \
                     enforced with {want}",
                    receipt["phase"]
                ));
            }
            if receipt["lifetime"]["native"]["details"]["test_seams"][state::ABORT_AT_SEAM]
                != label.as_str()
            {
                problems.push(format!("{label}: the receipt does not record the seam"));
            }
        }
        Ok(None) => problems.push(format!("{label}: no jail.json")),
        Err(problem) => problems.push(format!("{label}: {problem}")),
    }
    if let Some(copy) = &run.receipt_path
        && let Ok(Some(value)) = parse(copy)
        && let Err(error) = common::check_receipt(&value)
    {
        problems.push(format!(
            "{label}: the --receipt copy fails the contract: {error}"
        ));
    }
    let temps = leftover(&data, &dir);
    if !temps_match(&temps, "jail.json", point) {
        problems.push(format!(
            "{label}: leftover temporary files {temps:?}; a crash here leaves {} of \
             `.jail.json.*.tmp`",
            u8::from(point.temp_left)
        ));
    }
    let before = present(&dir);
    let gc = gc_run(&data, None);
    if serde_json::from_slice::<Value>(&gc.stdout).is_err() {
        problems.push(format!(
            "{label}: gc printed no report: {}",
            String::from_utf8_lossy(&gc.stderr)
        ));
    }
    kept(&label, &dir, &before, &mut problems);
    eprintln!("{label}: leftover {temps:?}");
    drop(run);
    problems
}

#[test]
fn j5_r02_a_crash_at_each_point_of_the_integrity_receipt_leaves_valid_records() {
    if !live() {
        return;
    }
    let problems: Vec<String> = POINTS.into_iter().flat_map(integrity_crash).collect();
    assert_no_problems(&problems);
}

// ===========================================================================
// P12: gc resuming a pending vendor-state cleanup
// ===========================================================================

/// A `tool` attempt with vendor state whose supervisor died right after its
/// settled receipt with `state_cleanup = pending` was durable (P8), before it
/// removed anything: the cleanup gc resumes.
fn pending_cleanup() -> Result<(Run, PathBuf), String> {
    let jail = aborting_jail();
    let launch = jail.config_dir().join("launch");
    std::fs::create_dir_all(&launch).unwrap();
    let profile = launch.join("plain.toml");
    std::fs::write(
        &profile,
        "name = \"plain\"\njail = \"tool\"\nstate_subdirs = [\"a/b\"]\n",
    )
    .unwrap();
    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o600)).unwrap();
    let workspace = private_workspace(&jail);
    let data = jail.data_dir();
    let run = jail
        .arg("run")
        .args(["--profile", "tool", "--launch", "plain", "--workspace"])
        .arg(&workspace)
        .env(state::ABORT_AT_SEAM, "pending_receipt:dir_synced")
        .target(["/bin/true"])
        .run()
        .expect("the run");
    if run.signal() != Some(libc::SIGABRT) {
        return Err(format!(
            "the supervisor was not aborted after its pending receipt (exit {:?}): {}",
            run.code(),
            run.stderr_text().trim()
        ));
    }
    let dir = the_attempt(&data)?;
    let receipt = read_json(&dir.join("jail.json"));
    let state = read_json(&dir.join("jail-state.json"));
    if receipt["phase"] != "settled"
        || receipt["state_cleanup"] != "pending"
        || state["state_cleanup"] != "pending"
        || !dir.join("vendor-state").is_dir()
    {
        return Err(format!(
            "no pending cleanup to resume: receipt {} / {}, state {}, vendor state present {}",
            receipt["phase"],
            receipt["state_cleanup"],
            state["state_cleanup"],
            dir.join("vendor-state").is_dir()
        ));
    }
    Ok((run, dir))
}

/// One crash at `point` of gc's `nth` replacement at P12 in one pass: the
/// receipt it completes (1), or jail state (2) right after it. Vendor
/// state is removed before either record, so it is gone whichever record
/// the crash interrupted; the replaced record is the prior one before the
/// rename and the completed one after it; the next pass finishes.
fn resume_crash(point: Point, nth: usize) -> Vec<String> {
    let label = format!("gc_resume:{}:{nth}", point.name);
    let mut problems = Vec::new();
    let (run, dir) = match pending_cleanup() {
        Ok(found) => found,
        Err(problem) => {
            problems.push(format!("{label}: {problem}"));
            return problems;
        }
    };
    let data = run.data_dir.clone();
    let _leaf = LeafGuard::of(&dir);
    let revision = read_json(&dir.join("jail.json"))["revision"]
        .as_u64()
        .unwrap_or(0);
    // One pass: the receipt is P12's first replacement, jail state its second.
    if !gc_crash(&label, &data, &label, &mut problems) {
        return problems;
    }
    records_valid(&label, &dir, &mut problems);
    let receipt = read_json(&dir.join("jail.json"));
    let state = read_json(&dir.join("jail-state.json"));
    let receipt_done = nth == 2 || point.published;
    let state_done = nth == 2 && point.published;
    let word = |done: bool| if done { "complete" } else { "pending" };
    let revision_now = receipt["revision"].as_u64().unwrap_or(0);
    if receipt["state_cleanup"] != word(receipt_done)
        || revision_now != revision + u64::from(receipt_done)
    {
        problems.push(format!(
            "{label}: the receipt says {} at revision {revision_now} (was {revision}); a crash \
             here leaves {}",
            receipt["state_cleanup"],
            word(receipt_done)
        ));
    }
    if state["state_cleanup"] != word(state_done) {
        problems.push(format!(
            "{label}: jail state says {}; a crash here leaves {}",
            state["state_cleanup"],
            word(state_done)
        ));
    }
    if dir.join("vendor-state").exists() {
        problems.push(format!(
            "{label}: a record of the cleanup was written before vendor state was removed"
        ));
    }
    let record = if nth == 1 {
        "jail.json"
    } else {
        "jail-state.json"
    };
    let temps = leftover(&data, &dir);
    if !temps_match(&temps, record, point) {
        problems.push(format!(
            "{label}: leftover temporary files {temps:?}; a crash here leaves {} of \
             `.{record}.*.tmp`",
            u8::from(point.temp_left)
        ));
    }
    let before = present(&dir);
    gc_finishes(&label, &data, &mut problems);
    kept(&label, &dir, &before, &mut problems);
    let receipt = read_json(&dir.join("jail.json"));
    let state = read_json(&dir.join("jail-state.json"));
    if receipt["state_cleanup"] != "complete"
        || state["state_cleanup"] != "complete"
        || receipt["revision"].as_u64() != Some(revision + 1)
    {
        problems.push(format!(
            "{label}: after the next pass the receipt says {} at revision {} and jail state {}",
            receipt["state_cleanup"], receipt["revision"], state["state_cleanup"]
        ));
    }
    let temps = leftover(&data, &dir);
    if !temps.is_empty() {
        problems.push(format!("{label}: the next pass left {temps:?}"));
    }
    eprintln!("{label}: ok={}", problems.is_empty());
    problems
}

#[test]
fn j5_r02_a_crash_at_each_point_of_both_gc_resume_writes_leaves_valid_records() {
    if !live() {
        return;
    }
    let mut problems = Vec::new();
    for nth in [1, 2] {
        for point in POINTS {
            problems.extend(resume_crash(point, nth));
        }
    }
    assert_no_problems(&problems);
}

// ===========================================================================
// P13: gc's record of a dead attempt's proxy directory
// ===========================================================================

/// One crash at `point` of gc's proxy-directory record (P13). An `agent`
/// supervisor died right after its prepared receipt, leaving its registered
/// proxy directory; gc removes it and records that in jail state. The
/// directory is gone whichever side of the rename the crash fell on; jail
/// state says so exactly after the rename; the next pass records it.
fn proxy_crash(point: Point) -> Vec<String> {
    let label = format!("gc_proxy_dir:{}", point.name);
    let mut problems = Vec::new();
    let jail = aborting_jail();
    let workspace = private_workspace(&jail);
    let data = jail.data_dir();
    let run = jail
        .arg("run")
        .args(["--profile", "agent", "--workspace"])
        .arg(&workspace)
        .env(state::ABORT_AT_SEAM, "prepared_receipt:dir_synced")
        .target(["/bin/true"])
        .run()
        .expect("the run");
    if run.signal() != Some(libc::SIGABRT) {
        problems.push(format!(
            "{label}: the supervisor was not aborted after its prepared receipt (exit {:?}): {}",
            run.code(),
            run.stderr_text().trim()
        ));
        return problems;
    }
    let dir = match the_attempt(&data) {
        Ok(dir) => dir,
        Err(problem) => {
            problems.push(format!("{label}: {problem}"));
            return problems;
        }
    };
    let _leaf = LeafGuard::of(&dir);
    if let Some((leaf, _)) = registered_leaf(&dir) {
        wait_for("the dead supervisor's leaf to empty", || {
            !leaf.exists() || !populated(&leaf)
        });
    }
    let proxy = dir.join(state::PROXY_DIR_NAME);
    let state = read_json(&dir.join("jail-state.json"));
    if !proxy.is_dir() || state["proxy_dir"]["removed"] != false {
        problems.push(format!(
            "{label}: no registered proxy directory to collect (present {}): {}",
            proxy.is_dir(),
            state["proxy_dir"]
        ));
        return problems;
    }
    if !gc_crash(&label, &data, &label, &mut problems) {
        return problems;
    }
    records_valid(&label, &dir, &mut problems);
    let state = read_json(&dir.join("jail-state.json"));
    let removed = state["proxy_dir"]["removed"] == true;
    if removed != point.published {
        problems.push(format!(
            "{label}: jail state says removed={removed}; a crash here leaves {}: {}",
            point.published, state["proxy_dir"]
        ));
    }
    if proxy.exists() {
        problems.push(format!(
            "{label}: the proxy directory is still there although gc reached its record"
        ));
    }
    let temps = leftover(&data, &dir);
    if !temps_match(&temps, "jail-state.json", point) {
        problems.push(format!(
            "{label}: leftover temporary files {temps:?}; a crash here leaves {} of \
             `.jail-state.json.*.tmp`",
            u8::from(point.temp_left)
        ));
    }
    let before = present(&dir);
    gc_finishes(&label, &data, &mut problems);
    kept(&label, &dir, &before, &mut problems);
    let state = read_json(&dir.join("jail-state.json"));
    if state["proxy_dir"]["removed"] != true || state["proxy_dir"]["removed_by"] != "gc" {
        problems.push(format!(
            "{label}: after the next pass: {}",
            state["proxy_dir"]
        ));
    }
    let temps = leftover(&data, &dir);
    if !temps.is_empty() {
        problems.push(format!("{label}: the next pass left {temps:?}"));
    }
    eprintln!("{label}: ok={}", problems.is_empty());
    problems
}

#[test]
fn j5_r02_a_crash_at_each_point_of_the_gc_proxy_dir_record_leaves_valid_records() {
    if !live() {
        return;
    }
    let problems: Vec<String> = POINTS.into_iter().flat_map(proxy_crash).collect();
    assert_no_problems(&problems);
}

// ===========================================================================
// P14: each of gc's records, in the order one pass writes them
// ===========================================================================

/// What a dead supervisor left for gc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Left {
    /// A `none` supervisor killed while its target's descendant still runs:
    /// its registered leaf is populated and nothing else ends it (§8.2), so
    /// gc terminates the orphan first.
    PopulatedLeaf,
    /// A `tool` supervisor aborted right after its enforced receipt: its
    /// watcher ended the tree, so the leaf is empty, and the managed scratch
    /// is there.
    EmptyLeaf,
}

/// A fresh attempt whose supervisor died leaving `left`, and the guard of
/// its leaf.
fn dead_supervisor(left: Left) -> Result<(Run, PathBuf, Option<LeafGuard>), String> {
    let run = match left {
        Left::PopulatedLeaf => {
            let jail = Jail::new().expect("a private harness");
            let workspace = private_workspace(&jail);
            let running = jail.root().join("running");
            let code = format!(
                "import os, time\n\
                 null = os.open('/dev/null', os.O_RDWR)\n\
                 for fd in (0, 1, 2): os.dup2(null, fd)\n\
                 if os.fork() == 0:\n\
                 \x20   time.sleep(120)\n\
                 \x20   os._exit(0)\n\
                 open({running:?}, 'w').write(str(os.getpid()))\n\
                 time.sleep(120)\n",
                running = running.to_str().unwrap(),
            );
            let spawned = jail
                .arg("run")
                .args(["--profile", "none", "--observe", "off", "--workspace"])
                .arg(&workspace)
                .receipt()
                .target([PYTHON, "-c", &code])
                .spawn()
                .expect("the jail starts");
            let enforced = wait_for("the target to run", || {
                running.exists()
                    && spawned
                        .receipt_value()
                        .is_some_and(|r| r["phase"] == "enforced")
            });
            // The process the harness spawned: this test's own supervisor.
            let supervisor = identity::pidfd_open(spawned.pid() as i32)
                .map_err(|error| format!("the supervisor's pidfd: {error}"))?;
            identity::pidfd_send_signal(supervisor.as_raw_fd(), libc::SIGKILL)
                .map_err(|error| format!("killing the supervisor: {error}"))?;
            let run = spawned.wait().expect("the harness collects the supervisor");
            if !enforced || run.signal() != Some(libc::SIGKILL) {
                return Err(format!(
                    "the supervisor did not die enforced (signal {:?}): {}",
                    run.signal(),
                    run.stderr_text().trim()
                ));
            }
            run
        }
        Left::EmptyLeaf => {
            let jail = aborting_jail();
            let workspace = private_workspace(&jail);
            let run = jail
                .arg("run")
                .args(["--profile", "tool", "--workspace"])
                .arg(&workspace)
                .env(state::ABORT_AT_SEAM, "enforced_receipt:dir_synced")
                .target(["/bin/sleep", "30"])
                .run()
                .expect("the run");
            if run.signal() != Some(libc::SIGABRT) {
                return Err(format!(
                    "the supervisor was not aborted after its enforced receipt (exit {:?}): {}",
                    run.code(),
                    run.stderr_text().trim()
                ));
            }
            run
        }
    };
    let dir = the_attempt(&run.data_dir)?;
    let guard = LeafGuard::of(&dir);
    let Some((leaf, _)) = registered_leaf(&dir) else {
        return Err("jail state registers no leaf".to_owned());
    };
    match left {
        Left::PopulatedLeaf => {
            if !populated(&leaf) {
                return Err("the dead supervisor's leaf is not populated".to_owned());
            }
        }
        Left::EmptyLeaf => {
            if !wait_for("the dead supervisor's leaf to empty", || !populated(&leaf)) {
                return Err("the dead supervisor's leaf never emptied".to_owned());
            }
            std::fs::write(dir.join("scratch").join("left-behind"), b"x")
                .map_err(|error| format!("the managed scratch: {error}"))?;
        }
    }
    Ok((run, dir, guard))
}

fn gc_actions(dir: &Path) -> Vec<String> {
    parse(&dir.join("jail-state.json"))
        .ok()
        .flatten()
        .map(|state| actions_of(&state))
        .unwrap_or_default()
}

fn actions_of(state: &Value) -> Vec<String> {
    state["gc_actions"]
        .as_array()
        .map(|actions| {
            actions
                .iter()
                .filter_map(|action| action["action"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The records one uninterrupted gc pass writes over what `left` leaves, in
/// order; that pass must finish everything.
fn record_sequence(left: Left) -> Result<Vec<String>, String> {
    let (run, dir, _guard) = dead_supervisor(left)?;
    let leaf = registered_leaf(&dir).map(|(path, _)| path);
    let mut problems = Vec::new();
    gc_finishes(&format!("{left:?} sequence"), &run.data_dir, &mut problems);
    if leaf.is_some_and(|leaf| leaf.exists()) || dir.join("scratch").exists() {
        problems.push("the pass left the leaf or the scratch".to_owned());
    }
    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    Ok(gc_actions(&dir))
}

/// Whether the leaf and the managed scratch are where the records' order
/// puts them at a crash in the `nth` record (§14.2, S6, G3): nothing killed
/// before `gc_terminating_orphan` is durable, the leaf seen empty by
/// `gc_terminated_orphan`, still there at `gc_removing_cgroup` (the intent
/// precedes the `rmdir`), gone by `gc_removed_cgroup` and after it; the
/// scratch there until `gc_removed_scratch`, which follows its removal.
fn order_problem(
    sequence: &[String],
    nth: usize,
    leaf: &Path,
    pinned: Option<u64>,
    scratch: &Path,
) -> Option<String> {
    let action = sequence[nth - 1].as_str();
    let before = &sequence[..nth - 1];
    let there = pinned.is_some_and(|pinned| inode(leaf) == Some(pinned));
    let full = there && populated(leaf);
    let leaf_ok = if before.iter().any(|done| done == "gc_removed_cgroup") {
        !leaf.exists()
    } else {
        match action {
            "gc_terminating_orphan" => full,
            "gc_terminated_orphan" | "gc_removing_cgroup" => there && !populated(leaf),
            "gc_removed_cgroup" => !leaf.exists(),
            _ => true,
        }
    };
    let has_scratch = sequence.iter().any(|done| done == "gc_removed_scratch");
    let scratch_gone =
        action == "gc_removed_scratch" || before.iter().any(|done| done == "gc_removed_scratch");
    let scratch_ok = !has_scratch || scratch.exists() != scratch_gone;
    (!leaf_ok || !scratch_ok).then(|| {
        format!(
            "at {action}: leaf present {} populated {}, scratch present {}",
            leaf.exists(),
            populated(leaf),
            scratch.exists()
        )
    })
}

/// One crash at `point` of the `nth` record of a pass over what `left`
/// leaves, whose uninterrupted records are `sequence`.
fn record_crash(left: Left, sequence: &[String], nth: usize, point: Point) -> Vec<String> {
    let action = &sequence[nth - 1];
    let label = format!("gc_record:{}:{nth}", point.name);
    let described = format!("{left:?} {action} ({label})");
    let mut problems = Vec::new();
    let (run, dir, _guard) = match dead_supervisor(left) {
        Ok(found) => found,
        Err(problem) => {
            problems.push(format!("{described}: {problem}"));
            return problems;
        }
    };
    let data = run.data_dir.clone();
    let (leaf, pinned) = registered_leaf(&dir).expect("a registered leaf");
    let receipt_before = std::fs::read(dir.join("jail.json")).ok();
    if !gc_crash(&described, &data, &label, &mut problems) {
        return problems;
    }
    records_valid(&described, &dir, &mut problems);
    let durable = gc_actions(&dir);
    let done = if point.published { nth } else { nth - 1 };
    if durable != sequence[..done] {
        problems.push(format!(
            "{described}: jail state records {durable:?}; a crash here leaves {:?}",
            &sequence[..done]
        ));
    }
    if let Some(problem) = order_problem(sequence, nth, &leaf, pinned, &dir.join("scratch")) {
        problems.push(format!("{described}: {problem}"));
    }
    if std::fs::read(dir.join("jail.json")).ok() != receipt_before {
        problems.push(format!("{described}: gc rewrote the supervisor's receipt"));
    }
    let temps = leftover(&data, &dir);
    if !temps_match(&temps, "jail-state.json", point) {
        problems.push(format!(
            "{described}: leftover temporary files {temps:?}; a crash here leaves {} of \
             `.jail-state.json.*.tmp`",
            u8::from(point.temp_left)
        ));
    }
    // Before the rename, the temporary file holds the whole new state: the
    // record being written, on top of the ones before it.
    if point.temp_left
        && let Some(temp) = temps.first()
    {
        match parse(&dir.join(temp)) {
            Ok(Some(new)) if actions_of(&new) == sequence[..nth] => {}
            other => problems.push(format!(
                "{described}: the temporary file does not hold {:?}: {other:?}",
                &sequence[..nth]
            )),
        }
    }
    let before = present(&dir);
    gc_finishes(&described, &data, &mut problems);
    kept(&described, &dir, &before, &mut problems);
    // The next pass finishes. A crash between the `rmdir` and its record
    // leaves the intent as the last word on the leaf: the next pass finds
    // it gone and finishes from the intent (G3) without a
    // `gc_removed_cgroup` of its own (spec-proposal §2 item 25).
    let after = gc_actions(&dir);
    if !after.iter().any(|action| action == "gc_finished")
        || !after
            .iter()
            .any(|action| action == "gc_removed_cgroup" || action == "gc_removing_cgroup")
    {
        problems.push(format!(
            "{described}: after the next pass, no removal and gc_finished: {after:?}"
        ));
    }
    if leaf.exists() || dir.join("scratch").exists() {
        problems.push(format!(
            "{described}: stranded: leaf present {}, scratch present {}",
            leaf.exists(),
            dir.join("scratch").exists()
        ));
    }
    let temps = leftover(&data, &dir);
    if !temps.is_empty() {
        problems.push(format!("{described}: the next pass left {temps:?}"));
    }
    eprintln!("{described}: ok={}", problems.is_empty());
    problems
}

#[test]
fn j5_r02_a_crash_at_each_point_of_each_later_gc_record_leaves_valid_records() {
    if !live() {
        return;
    }
    let mut problems = Vec::new();
    let mut covered = std::collections::BTreeSet::new();
    for left in [Left::PopulatedLeaf, Left::EmptyLeaf] {
        let sequence = match record_sequence(left) {
            Ok(sequence) => sequence,
            Err(problem) => {
                problems.push(format!("{left:?}: {problem}"));
                continue;
            }
        };
        eprintln!("{left:?}: one pass records {sequence:?}");
        covered.extend(sequence.iter().cloned());
        for nth in 1..=sequence.len() {
            for point in POINTS {
                problems.extend(record_crash(left, &sequence, nth, point));
            }
        }
    }
    // Every record the J4 matrix left uncrashed is crashed here.
    for action in [
        "gc_terminating_orphan",
        "gc_terminated_orphan",
        "gc_removing_cgroup",
        "gc_removed_cgroup",
        "gc_removed_scratch",
        "gc_finished",
    ] {
        if !covered.contains(action) {
            problems.push(format!(
                "no pass recorded {action}, so it was never crashed"
            ));
        }
    }
    assert_no_problems(&problems);
}

// ===========================================================================
// R02.4: faults at P15 and P16, the execution leaf's name and identity
// ===========================================================================

/// One way a step of a durable replacement fails (as in R02.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    /// The disk is full: the first write fails with ENOSPC.
    Enospc,
    /// The first write stores half the bytes; the next one fails with EIO.
    ShortWriteThenEio,
    /// The file sync fails with EIO.
    FsyncError,
    /// The rename fails with EIO.
    RenameError,
    /// The directory sync after the rename fails with EIO.
    DirSyncError,
}

const FAULTS: [Fault; 5] = [
    Fault::Enospc,
    Fault::ShortWriteThenEio,
    Fault::FsyncError,
    Fault::RenameError,
    Fault::DirSyncError,
];

fn eio() -> std::io::Error {
    std::io::Error::from_raw_os_error(libc::EIO)
}

/// Performs every step for real and fails one step of the first
/// replacement at one site.
struct LeafFault {
    site: Site,
    fault: Fault,
    state: Mutex<LeafFaultState>,
}

#[derive(Default)]
struct LeafFaultState {
    /// Replacements seen at the site.
    at_site: usize,
    /// The replacement in progress is the one that fails.
    current: bool,
    fired: bool,
    short_pending: bool,
}

impl LeafFault {
    fn fire(&self, site: Site, fault: Fault) -> bool {
        let mut state = self.state.lock().unwrap();
        if site == self.site && state.current && !state.fired && self.fault == fault {
            state.fired = true;
            return true;
        }
        false
    }
}

impl PersistIo for LeafFault {
    fn create_new(&self, site: Site, path: &Path) -> std::io::Result<std::fs::File> {
        {
            let mut state = self.state.lock().unwrap();
            state.short_pending = false;
            state.current = false;
            if site == self.site {
                state.at_site += 1;
                state.current = state.at_site == 1;
            }
        }
        state::RealIo.create_new(site, path)
    }

    fn write(&self, site: Site, file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<usize> {
        if std::mem::take(&mut self.state.lock().unwrap().short_pending) {
            return Err(eio());
        }
        if self.fire(site, Fault::Enospc) {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
        }
        if self.fire(site, Fault::ShortWriteThenEio) {
            self.state.lock().unwrap().short_pending = true;
            return state::RealIo.write(site, file, &bytes[..(bytes.len() / 2).max(1)]);
        }
        state::RealIo.write(site, file, bytes)
    }

    fn sync_file(&self, site: Site, file: &std::fs::File) -> std::io::Result<()> {
        if self.fire(site, Fault::FsyncError) {
            return Err(eio());
        }
        state::RealIo.sync_file(site, file)
    }

    fn rename(&self, site: Site, from: &Path, to: &Path) -> std::io::Result<()> {
        if self.fire(site, Fault::RenameError) {
            return Err(eio());
        }
        state::RealIo.rename(site, from, to)
    }

    fn link(&self, site: Site, from: &Path, to: &Path) -> std::io::Result<()> {
        if self.fire(site, Fault::RenameError) {
            return Err(eio());
        }
        state::RealIo.link(site, from, to)
    }

    fn sync_dir(&self, site: Site, dir: &Path) -> std::io::Result<()> {
        if self.fire(site, Fault::DirSyncError) {
            return Err(eio());
        }
        state::RealIo.sync_dir(site, dir)
    }
}

/// A real attempt as a supervisor leaves it right before it names its leaf:
/// claimed, with its policy, and nothing else (the release binary aborted
/// once `policy.json` was durable, P2).
fn attempt_before_the_leaf() -> Result<(Run, PathBuf), String> {
    let jail = aborting_jail();
    let workspace = private_workspace(&jail);
    let data = jail.data_dir();
    let run = jail
        .arg("run")
        .args(["--profile", "tool", "--workspace"])
        .arg(&workspace)
        .env(state::ABORT_AT_SEAM, "policy:dir_synced")
        .target(["/bin/true"])
        .run()
        .expect("the run");
    if run.signal() != Some(libc::SIGABRT) {
        return Err(format!(
            "the supervisor was not aborted after its policy (exit {:?}): {}",
            run.code(),
            run.stderr_text().trim()
        ));
    }
    let dir = the_attempt(&data)?;
    let state = read_json(&dir.join("jail-state.json"));
    if !state["execution_cgroup"].is_null() || !leftover(&data, &dir).is_empty() {
        return Err(format!(
            "the attempt already names a leaf or has temporary files: {state:#}"
        ));
    }
    Ok((run, dir))
}

/// The execution-cgroup record jail state holds after a site's replacement.
fn leaf_record(path: &Path, identity: Option<(u64, u64)>) -> Value {
    serde_json::json!({
        "path": path.to_str().unwrap(),
        "device": identity.map(|(device, _)| device),
        "inode": identity.map(|(_, inode)| inode),
    })
}

/// One site crossed with one fault through the real leaf creation: the
/// creation refuses with `state_write_failed` (S5: a persistence failure
/// before exec), jail state is the prior record before the rename and the
/// new one after it (the directory sync is the only fault after it), no
/// temporary file is left (the failure is not a crash), no leaf is left
/// behind (P15 fails before `mkdir`; a P16 failure removes the empty leaf),
/// and a following gc keeps every record.
fn leaf_fault(site: Site, fault: Fault) -> Vec<String> {
    let label = format!("{}:{fault:?}", site.as_str());
    let mut problems = Vec::new();
    let (run, dir) = match attempt_before_the_leaf() {
        Ok(found) => found,
        Err(problem) => {
            problems.push(format!("{label}: {problem}"));
            return problems;
        }
    };
    let data = run.data_dir.clone();
    let id = AttemptId::parse(&dir.file_name().unwrap().to_string_lossy()).unwrap();
    // SAFETY: getuid takes no arguments and cannot fail.
    let root = cgroup::delegated_root(unsafe { libc::getuid() }).expect("a delegated subtree");
    let leaf = root.join(cgroup::leaf_name(&id));
    let prior = read_json(&dir.join("jail-state.json"));
    let policy = std::fs::read(dir.join("policy.json")).unwrap();
    let io = Arc::new(LeafFault {
        site,
        fault,
        state: Mutex::default(),
    });
    let limits = LimitsSnapshot {
        wall: None,
        pids: None,
        mem: None,
        cpu: None,
    };
    let created = state::with_persist_io(io.clone(), || {
        ExecutionCgroup::create_for_attempt(&limits, &dir)
    });
    let identity = inode(&leaf);
    match created {
        Err(error) if error.code == ErrorCode::StateWriteFailed => {}
        Err(error) => problems.push(format!(
            "{label}: the creation refused with {:?}, not state_write_failed: {}",
            error.code, error.message
        )),
        Ok(Ok(made)) => {
            problems.push(format!(
                "{label}: the leaf was created although its registration failed"
            ));
            drop(made);
        }
        Ok(Err(error)) => problems.push(format!(
            "{label}: the creation failed for another reason: {error}"
        )),
    }
    if !io.state.lock().unwrap().fired {
        problems.push(format!(
            "{label}: the fault was never injected: the site performs no such step"
        ));
    }
    records_valid(&label, &dir, &mut problems);
    let state = read_json(&dir.join("jail-state.json"));
    let renamed = fault == Fault::DirSyncError;
    let expected = match (site, renamed) {
        (Site::ExecutionLeaf, false) => Value::Null,
        (Site::ExecutionLeaf, true) | (_, false) => leaf_record(&leaf, None),
        (_, true) => state["execution_cgroup"].clone(),
    };
    if state["execution_cgroup"] != expected {
        problems.push(format!(
            "{label}: jail state names {}; a failure here leaves {expected}",
            state["execution_cgroup"]
        ));
    }
    if site == Site::ExecutionLeafIdentity
        && renamed
        && (state["execution_cgroup"]["path"] != leaf.to_str().unwrap()
            || !state["execution_cgroup"]["inode"].is_u64())
    {
        problems.push(format!(
            "{label}: after the rename jail state identifies no leaf: {}",
            state["execution_cgroup"]
        ));
    }
    let mut unchanged = state.clone();
    match (prior.get("execution_cgroup"), unchanged.as_object_mut()) {
        (Some(record), Some(fields)) => {
            fields.insert("execution_cgroup".to_owned(), record.clone());
        }
        (None, Some(fields)) => {
            fields.remove("execution_cgroup");
        }
        _ => {}
    }
    if unchanged != prior {
        problems.push(format!(
            "{label}: the failed write changed more than the leaf's record"
        ));
    }
    if std::fs::read(dir.join("policy.json")).unwrap() != policy {
        problems.push(format!("{label}: policy.json changed"));
    }
    let temps = leftover(&data, &dir);
    if !temps.is_empty() {
        problems.push(format!(
            "{label}: a failed write that was not a crash left temporary files: {temps:?}"
        ));
    }
    if identity.is_some() {
        problems.push(format!(
            "{label}: a leaf was left behind at {}",
            leaf.display()
        ));
        // Ours: named by this attempt's id, made by this call, and empty.
        if !populated(&leaf) {
            let _ = std::fs::remove_dir(&leaf);
        }
    }
    let before = present(&dir);
    let gc = gc_run(&data, None);
    if serde_json::from_slice::<Value>(&gc.stdout).is_err() {
        problems.push(format!(
            "{label}: gc printed no report: {}",
            String::from_utf8_lossy(&gc.stderr)
        ));
    }
    kept(&label, &dir, &before, &mut problems);
    eprintln!("{label}: ok={}", problems.is_empty());
    problems
}

#[test]
fn j5_r02_every_fault_at_the_execution_leaf_sites_leaves_valid_records() {
    if !live() {
        return;
    }
    let mut problems = Vec::new();
    for site in [Site::ExecutionLeaf, Site::ExecutionLeafIdentity] {
        for fault in FAULTS {
            problems.extend(leaf_fault(site, fault));
        }
    }
    assert_no_problems(&problems);
}
