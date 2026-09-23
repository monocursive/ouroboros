//! J4 slice G, portable: what `gc` may do with an attempt a supervisor left
//! behind (jail-v1 §7, §14.2, §15 C03).
//!
//! C03: "GC skips live/foreign/unidentified resources; boot/PID/cgroup reuse
//! does not target an unrelated process." These run natively on macOS and on
//! Linux. Attempts are built on disk by hand, in the shapes the supervisor
//! writes them (a free or held `jail.lock`, a claimed `jail-state.json`, a
//! receipt taken from the checked-in examples), and `gc` runs through the
//! real library entry point (`supervisor::gc`, `gc::gc_with`) or the real
//! binary. Where a decision depends on the host (the recorded owner's
//! liveness, the execution cgroup), a scripted host answers and records every
//! call, so "never probes" and "never kills" are assertions, not hopes.
//!
//! What this file does not prove: that the Linux mechanisms do what the
//! scripted host says. `j4_gc_linux.rs` kills, verifies and removes a real
//! orphan leaf on the reference host.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ouro_jail::capability::Capability;
use ouro_jail::cli;
use ouro_jail::config::EnvSettings;
use ouro_jail::platform::{
    OwnerIdentity, PlanRequest, Platform, PlatformIdentity, PreparedExecution, PreparedPlan, Sinks,
};
use ouro_jail::records::{JailError, Os};
use ouro_jail::state::{self, AttemptDir, AttemptId};
use ouro_jail::supervisor;
use serde_json::{Value, json};

mod common;

/// The boot the simulated host is in.
const HOST_BOOT: &str = "00000000-0000-4000-8000-00000000b001";
/// Some other boot of the same host.
const OTHER_BOOT: &str = "00000000-0000-4000-8000-00000000b002";
/// The simulated host's architecture string.
const SIM_ARCH: &str = "simulation";

// ---------------------------------------------------------------------------
// The simulated platform: gc asks it who it is and nothing else
// ---------------------------------------------------------------------------

struct SimPlatform;

impl Platform for SimPlatform {
    fn owner_identity(&self) -> Option<OwnerIdentity> {
        Some(OwnerIdentity {
            pid: std::process::id(),
            boot_id: HOST_BOOT.to_owned(),
            start_time_ticks: 1,
        })
    }
    fn identity(&self) -> PlatformIdentity {
        PlatformIdentity {
            os: Os::Linux,
            arch: SIM_ARCH.to_owned(),
            kernel: "simulated".to_owned(),
        }
    }
    fn probe(&self, _: &PlanRequest) -> Vec<Capability> {
        unreachable!("gc probes no capability")
    }
    fn prepare(&self, _: PreparedPlan, _: Sinks) -> Result<Box<dyn PreparedExecution>, JailError> {
        unreachable!("gc prepares nothing")
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    data: PathBuf,
    workspace: PathBuf,
    outside: PathBuf,
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn json_file(path: &Path, value: &Value) {
    private_file(path, &serde_json::to_vec_pretty(value).unwrap());
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

impl Fixture {
    fn new() -> Fixture {
        let dir = common::private_tempdir();
        // Canonical, so that macOS's /var -> /private/var alias is not a
        // symlink on any no-follow walk.
        let root = dir.path().canonicalize().unwrap();
        let fixture = Fixture {
            config: root.join("config"),
            data: root.join("data"),
            workspace: root.join("workspace"),
            outside: root.join("outside"),
            root,
            _root: dir,
        };
        for path in [
            &fixture.config,
            &fixture.data,
            &fixture.workspace,
            &fixture.outside,
        ] {
            private_dir(path);
        }
        private_dir(&fixture.data.join("attempts"));
        fixture
    }

    fn context(&self) -> supervisor::Context {
        self.context_for(self.data.clone())
    }

    fn context_for(&self, data: PathBuf) -> supervisor::Context {
        supervisor::Context {
            platform: Box::new(SimPlatform),
            env_settings: EnvSettings {
                config_dir: Some(self.config.clone()),
                data_dir: Some(data),
                ..Default::default()
            },
            cwd: self.workspace.clone(),
            home: Some(self.root.join("home")),
            env_lookup: Box::new(|_| None),
        }
    }

    /// `gc` through the entry point the J3 tests use.
    fn gc(&self, dry_run: bool) -> Result<supervisor::GcReport, JailError> {
        supervisor::gc(&self.context(), &gc_args(dry_run))
    }

    /// The real binary on this host, over this fixture's state root.
    fn binary(&self, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_ouro-jail"));
        command
            .args(args)
            .current_dir(&self.workspace)
            .env("OURO_CONFIG_DIR", &self.config)
            .env("OURO_DATA_DIR", &self.data)
            .env("HOME", self.root.join("home"));
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    /// A private attempt root under `<data>/attempts/`, nothing in it.
    fn root_of(&self, id: &str) -> AttemptDir {
        let dir = AttemptDir::new(&self.data, &AttemptId::parse(id).unwrap());
        dir.create(&self.data).unwrap();
        dir
    }
}

fn gc_args(dry_run: bool) -> cli::GcArgs {
    cli::GcArgs {
        dry_run,
        json: false,
    }
}

fn fresh_id() -> String {
    AttemptId::generate().as_str().to_owned()
}

/// A process id that names no live supervisor: a child this test started and
/// reaped. Recorded with a birth time of 1 tick, which no process has.
fn dead_pid() -> u32 {
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    pid
}

// ---------------------------------------------------------------------------
// Attempt builders: the shapes the supervisor writes
// ---------------------------------------------------------------------------

/// A `jail.lock` whose lease nobody holds: the supervisor that created it is
/// gone (the lock file is created, then locked, by `Lease::acquire`).
fn free_lock(dir: &AttemptDir) {
    drop(
        state::Lease::acquire(&dir.lock_path())
            .unwrap()
            .expect("a fresh lease is free"),
    );
}

/// The claim `claim_attempt` writes (§7), for a platform and an owner.
fn claim(dir: &AttemptDir, os: &str, arch: &str, owner: Option<(u32, &str, u64)>) -> Value {
    let id = dir.root().file_name().unwrap().to_str().unwrap().to_owned();
    let state = json!({
        "schema": "ouro.jail.state/1",
        "attempt_id": id,
        "os": os,
        "arch": arch,
        "kernel": "simulated",
        "component_version": "0.0.0",
        "claimed_at": "2026-09-23T00:00:00Z",
        "owner": owner.map_or(Value::Null, |(pid, boot, ticks)| json!({
            "pid": pid,
            "boot_id": boot,
            "start_time_ticks": ticks,
        })),
        "boundary": Value::Null,
        "vendor_state": Value::Null,
        "state_cleanup": "not_needed",
    });
    json_file(&dir.state_path(), &state);
    state
}

/// The claim of a Linux supervisor on the simulated host, now dead.
fn claim_dead_owner(dir: &AttemptDir, boot: &str) -> Value {
    claim(dir, "linux", SIM_ARCH, Some((dead_pid(), boot, 1)))
}

/// Registers and creates vendor state the way `create_vendor_state` does, with
/// a file in it, and leaves its cleanup `pending`.
fn vendor_state_pending(dir: &AttemptDir) -> PathBuf {
    use std::os::unix::fs::MetadataExt as _;
    let vendor = dir.vendor_state_path();
    private_dir(&vendor);
    private_file(&vendor.join("precious"), b"vendor state");
    let meta = std::fs::metadata(&vendor).unwrap();
    let mut state = read_json(&dir.state_path());
    state["vendor_state"] = json!({
        "name": "vendor-state",
        "registered_at": "2026-09-23T00:00:00Z",
        "dev": meta.dev().to_string(),
        "ino": meta.ino().to_string(),
        "credentials": [],
    });
    state["state_cleanup"] = json!("pending");
    state["cleanup_reason"] = Value::Null;
    json_file(&dir.state_path(), &state);
    vendor
}

fn example(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs/jail-v1/examples")
        .join(name);
    read_json(&path)
}

/// A settled receipt whose verified tree death permits the pending
/// vendor-state cleanup (`cleanup::permitted_by`).
fn settled_receipt(dir: &AttemptDir, boot: &str) -> Value {
    let mut receipt = example("receipt-tool.json");
    receipt["attempt_id"] = json!(dir.root().file_name().unwrap().to_str().unwrap());
    receipt["state_cleanup"] = json!("pending");
    receipt["process"]["identity"]["value"]["boot_id"] = json!(boot);
    json_file(&dir.receipt_path(), &receipt);
    receipt
}

/// The last receipt of a `none` supervisor that died after release: phase
/// `enforced`, tree result unknown, and the execution leaf it registered.
fn enforced_receipt_with_leaf(dir: &AttemptDir, boot: &str, leaf: &gc_leaf::Leaf) -> Value {
    let mut receipt = example("receipt-none-prepared.json");
    receipt["attempt_id"] = json!(dir.root().file_name().unwrap().to_str().unwrap());
    receipt["phase"] = json!("enforced");
    receipt["exec_observed"] = json!(true);
    receipt["process"]["identity"]["value"]["boot_id"] = json!(boot);
    receipt["lifetime"]["native"]["details"] = json!({
        "execution_cgroup": {
            "path": leaf.path,
            "device": leaf.device,
            "inode": leaf.inode,
            "charged_helpers": [],
            "scope": "target_descendants_and_listed_helpers",
        },
        "launcher_pid": 1234,
        "child_subreaper": true,
    });
    json_file(&dir.receipt_path(), &receipt);
    receipt
}

mod gc_leaf {
    /// A recorded execution leaf, as the receipt's native details name it.
    pub struct Leaf {
        pub path: String,
        pub device: u64,
        pub inode: u64,
    }

    pub fn sample() -> Leaf {
        Leaf {
            path: "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/\
                   ouro-att_00000000-0000-4000-8000-00000000c001.leaf"
                .to_owned(),
            device: 30,
            inode: 4242,
        }
    }
}

/// Managed scratch, as the contained profile creates it, with `files` files,
/// and the `policy.json` that says it is managed.
fn managed_scratch(dir: &AttemptDir, files: usize) -> PathBuf {
    let scratch = dir.scratch_path();
    private_dir(&scratch);
    for index in 0..files {
        private_file(&scratch.join(format!("f{index}")), b"scratch");
    }
    json_file(
        &dir.policy_path(),
        &json!({"snapshot": {"roots": {"scratch": {"kind": "managed"}}}}),
    );
    scratch
}

// ---------------------------------------------------------------------------
// A picture of a tree: what a dry run must leave exactly as it was
// ---------------------------------------------------------------------------

#[derive(PartialEq, Eq, Debug)]
enum Node {
    Dir(u32),
    File(u32, Vec<u8>),
    Link(PathBuf),
}

fn picture(root: &Path) -> BTreeMap<PathBuf, Node> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let meta = std::fs::symlink_metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o7777;
        let node = if meta.file_type().is_symlink() {
            Node::Link(std::fs::read_link(&path).unwrap())
        } else if meta.is_dir() {
            for entry in std::fs::read_dir(&path).unwrap() {
                stack.push(entry.unwrap().path());
            }
            Node::Dir(mode)
        } else {
            Node::File(mode, std::fs::read(&path).unwrap())
        };
        out.insert(path, node);
    }
    out
}

fn entry<'a>(report: &'a supervisor::GcReport, id: &str) -> &'a supervisor::GcEntry {
    report
        .entries
        .iter()
        .find(|entry| entry.attempt_id == id)
        .unwrap_or_else(|| panic!("no entry for {id}"))
}

// ===========================================================================
// Leases and unclaimed roots (§7, §14.2; N5 and the claim race)
// ===========================================================================

/// §14.2: "Active locks ... are retained." A claimed attempt whose supervisor
/// still holds the lease is not touched, even when its receipt would permit
/// the pending cleanup. (Covered at the lease level since D3; kept as C03's
/// row.)
#[test]
fn j4_c03_a_live_lease_is_retained() {
    let fixture = Fixture::new();
    let id = fresh_id();
    let dir = fixture.root_of(&id);
    let held = state::Lease::acquire(&dir.lock_path())
        .unwrap()
        .expect("the lease is free");
    claim_dead_owner(&dir, HOST_BOOT);
    let vendor = vendor_state_pending(&dir);
    settled_receipt(&dir, HOST_BOOT);
    for dry_run in [true, false] {
        let before = picture(&fixture.data);
        let report = fixture.gc(dry_run).expect("gc scans");
        let entry = entry(&report, &id);
        assert_eq!(entry.action, "retained", "{}", entry.reason);
        assert!(entry.reason.contains("live supervisor"), "{}", entry.reason);
        assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
        assert_eq!(picture(&fixture.data), before, "dry_run={dry_run}");
        assert!(vendor.join("precious").is_file());
    }
    drop(held);
}

/// §14.2: "Never ... delete a directory solely because its name looks like an
/// attempt id" — and never act on one whose name is not an attempt id at
/// all: a full attempt layout under a malformed name is skipped and
/// untouched, dry or not.
#[test]
fn j4_c03_a_name_that_is_not_an_attempt_id_is_skipped() {
    let fixture = Fixture::new();
    let bogus = fixture.data.join("attempts").join("att_not-a-uuid");
    private_dir(&bogus);
    // The layout of an attempt this gc would otherwise clean.
    private_file(&bogus.join("jail.lock"), b"");
    private_file(&bogus.join("jail-state.json"), b"{}");
    private_dir(&bogus.join("vendor-state"));
    private_file(&bogus.join("vendor-state/precious"), b"not an attempt's");
    for dry_run in [true, false] {
        let before = picture(&fixture.data);
        let report = fixture.gc(dry_run).expect("gc scans");
        let entry = entry(&report, "att_not-a-uuid");
        assert_eq!(entry.action, "skipped", "{}", entry.reason);
        assert!(
            entry.reason.contains("not an attempt id"),
            "{}",
            entry.reason
        );
        assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
        assert_eq!(picture(&fixture.data), before, "dry_run={dry_run}");
    }
}

/// N5: a supervisor that died between taking the lease and claiming leaves
/// `jail.lock` and nothing else. That root is unclaimed: `gc` reports it and
/// exits 0 (§6.4: "0 for a completed scan (including skips reported with
/// reasons)"), dry run or not, and changes nothing on disk.
#[test]
fn j4_c03_an_unclaimed_root_without_state_is_a_reported_skip_with_exit_0() {
    let fixture = Fixture::new();
    let id = fresh_id();
    let dir = fixture.root_of(&id);
    free_lock(&dir);
    for args in [
        &["gc", "--json", "--dry-run"][..],
        &["gc", "--json"][..],
        &["gc"][..],
    ] {
        let before = picture(&fixture.data);
        let output = fixture.binary(args, &[]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {stderr}");
        assert_eq!(picture(&fixture.data), before, "{args:?} changed the tree");
        if args.contains(&"--json") {
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            let entry = &report["entries"][0];
            assert_eq!(entry["attempt_id"], id.as_str(), "{report:#}");
            assert_eq!(entry["action"], "retained", "{report:#}");
            assert!(
                entry["reason"]
                    .as_str()
                    .is_some_and(|reason| reason.contains("jail-state.json")),
                "{report:#}"
            );
        }
    }
}

/// The claim race (§7): the supervisor creates `jail.lock`, then locks it,
/// then claims `jail-state.json` while holding it. Between the create and the
/// lock the file exists with no lease on it. A `gc` that locks it there makes
/// that supervisor refuse `attempt_exists`. Deterministic half: the test holds
/// the lease of an unclaimed root the way a supervisor does between its lock
/// and its claim; `gc` must not have contended for it at all, so it reports
/// the root as unclaimed rather than as leased.
#[test]
fn j4_c03_gc_never_contends_for_the_lease_of_an_unclaimed_root() {
    let fixture = Fixture::new();
    let id = fresh_id();
    let dir = fixture.root_of(&id);
    let held = state::Lease::acquire(&dir.lock_path())
        .unwrap()
        .expect("the lease is free");
    for dry_run in [true, false] {
        let report = fixture.gc(dry_run).expect("gc scans");
        let entry = entry(&report, &id);
        assert_eq!(entry.action, "retained", "{}", entry.reason);
        assert!(
            !entry.reason.contains("live supervisor holds the lease"),
            "gc took the lock of an unclaimed root: {}",
            entry.reason
        );
        assert!(entry.reason.contains("jail-state.json"), "{}", entry.reason);
        assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
    }
    drop(held);
}

/// The claim race, end to end: the supervisor's own steps (`create`,
/// `check_fresh_attempt`, `Lease::acquire`) run in a loop on fresh roots while
/// `gc` scans the same state root in a loop on another thread. No claim may be
/// refused because `gc` held the lease of a root nobody had claimed yet.
#[test]
fn j4_c03_a_supervisor_taking_its_lease_is_never_refused_by_a_concurrent_gc() {
    let fixture = Fixture::new();
    let stop = AtomicBool::new(false);
    let (claims, refusals) = std::thread::scope(|scope| {
        scope.spawn(|| {
            let ctx = fixture.context();
            while !stop.load(Ordering::Relaxed) {
                let _ = supervisor::gc(&ctx, &gc_args(false));
            }
        });
        let mut claims = 0u64;
        let mut refusals = 0u64;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && claims + refusals < 50_000 {
            let id = AttemptId::generate();
            let dir = AttemptDir::new(&fixture.data, &id);
            dir.create(&fixture.data).unwrap();
            state::check_fresh_attempt(&dir).expect("a fresh root holds nothing");
            match state::Lease::acquire(&dir.lock_path()).unwrap() {
                Some(lease) => {
                    claims += 1;
                    drop(lease);
                }
                None => refusals += 1,
            }
            std::fs::remove_file(dir.lock_path()).unwrap();
            std::fs::remove_dir(dir.root()).unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        (claims, refusals)
    });
    assert!(claims > 0);
    assert_eq!(
        refusals,
        0,
        "{refusals} of {} lease acquisitions were refused while gc scanned",
        claims + refusals
    );
}

// ===========================================================================
// Identification before action: corrupt, foreign, outside the state root
// ===========================================================================

/// §14.2: "A corrupt state file causes quarantine-by-reporting and retention,
/// not guessed cleanup." A state that does not parse, names another schema or
/// another attempt is retained with its pending cleanup untouched, and the
/// report says why; §6.4 makes the failed state access exit 1.
/// Turns a valid claim into a corrupt one: in place, or as raw bytes.
type Corruption = fn(&mut Value) -> Option<Vec<u8>>;

#[test]
fn j4_c03_corrupt_state_is_retained_and_reported() {
    let cases: [(&str, Corruption); 3] = [
        ("not JSON", |_| {
            Some(b"{\"schema\": \"ouro.jail.state/1\",".to_vec())
        }),
        ("another schema", |state| {
            state["schema"] = json!("ouro.jail.state/0");
            None
        }),
        ("another attempt", |state| {
            state["attempt_id"] = json!("att_00000000-0000-4000-8000-0000000000ff");
            None
        }),
    ];
    for (label, corrupt) in cases {
        let fixture = Fixture::new();
        let id = fresh_id();
        let dir = fixture.root_of(&id);
        free_lock(&dir);
        claim_dead_owner(&dir, HOST_BOOT);
        let vendor = vendor_state_pending(&dir);
        settled_receipt(&dir, HOST_BOOT);
        let mut state = read_json(&dir.state_path());
        match corrupt(&mut state) {
            Some(bytes) => private_file(&dir.state_path(), &bytes),
            None => json_file(&dir.state_path(), &state),
        }
        for dry_run in [true, false] {
            let before = picture(&fixture.data);
            let report = fixture.gc(dry_run).expect("gc scans");
            let entry = entry(&report, &id);
            assert_eq!(entry.action, "retained", "{label}: {}", entry.reason);
            assert!(
                entry.reason.contains("corrupt"),
                "{label}: {}",
                entry.reason
            );
            assert!(
                report.incomplete.iter().any(|item| item.contains(&id)),
                "{label}: §6.4 failed state access: {:?}",
                report.incomplete
            );
            assert_eq!(picture(&fixture.data), before, "{label} dry_run={dry_run}");
            assert!(
                vendor.join("precious").is_file(),
                "{label}: guessed cleanup"
            );
        }
    }
}

/// §14.2: "foreign-platform resources are retained." An attempt claimed by
/// another OS or architecture is not this build's to clean, whatever its
/// receipt permits.
#[test]
fn j4_c03_a_foreign_os_or_architecture_is_retained() {
    for (os, arch) in [("macos", SIM_ARCH), ("linux", "riscv64")] {
        let fixture = Fixture::new();
        let id = fresh_id();
        let dir = fixture.root_of(&id);
        free_lock(&dir);
        claim(&dir, os, arch, Some((dead_pid(), HOST_BOOT, 1)));
        let vendor = vendor_state_pending(&dir);
        settled_receipt(&dir, HOST_BOOT);
        for dry_run in [true, false] {
            let before = picture(&fixture.data);
            let report = fixture.gc(dry_run).expect("gc scans");
            let entry = entry(&report, &id);
            assert_eq!(entry.action, "retained", "{os}/{arch}: {}", entry.reason);
            assert!(
                entry.reason.contains("foreign"),
                "{os}/{arch}: {}",
                entry.reason
            );
            assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
            assert_eq!(
                picture(&fixture.data),
                before,
                "{os}/{arch} dry_run={dry_run}"
            );
            assert!(vendor.join("precious").is_file());
        }
    }
}

/// A complete attempt `gc` would clean if it found it: free lease, a dead
/// owner, a settled receipt permitting the pending vendor-state cleanup.
fn cleanable_attempt(parent: &Path, id: &str) -> PathBuf {
    let root = parent.join(id);
    private_dir(&root);
    // `AttemptDir` is only a layout; build it over any parent.
    let dir = AttemptDir::new(
        root.parent().unwrap().parent().unwrap(),
        &AttemptId::parse(id).unwrap(),
    );
    assert_eq!(dir.root(), root);
    free_lock(&dir);
    claim_dead_owner(&dir, HOST_BOOT);
    let vendor = vendor_state_pending(&dir);
    settled_receipt(&dir, HOST_BOOT);
    vendor
}

/// §14.2: "`gc --dry-run` enumerates only the registered state root ... It
/// never discovers deletion targets by searching all of `/tmp`, HOME or
/// cgroupfs." An attempt-shaped directory beside `attempts/`, and a symlink
/// inside `attempts/` that names an attempt elsewhere, are never acted on;
/// the real attempt beside them is (so the scan did run).
#[test]
fn j4_c03_nothing_outside_the_attempts_directory_is_listed() {
    let fixture = Fixture::new();
    let attempts = fixture.data.join("attempts");
    let control = fresh_id();
    let control_vendor = cleanable_attempt(&attempts, &control);
    let beside_id = fresh_id();
    let beside = fixture.data.join("beside").join("attempts");
    private_dir(&beside);
    let beside_vendor = cleanable_attempt(&beside, &beside_id);
    let linked_id = fresh_id();
    let elsewhere = fixture.outside.join("attempts");
    private_dir(&elsewhere);
    let linked_vendor = cleanable_attempt(&elsewhere, &linked_id);
    std::os::unix::fs::symlink(elsewhere.join(&linked_id), attempts.join(&linked_id)).unwrap();

    let report = fixture.gc(false).expect("gc scans");
    assert!(
        !control_vendor.exists(),
        "the attempt under attempts/ was cleaned, so gc did scan: {:?}",
        report
            .entries
            .iter()
            .map(|e| (&e.attempt_id, &e.action, &e.reason))
            .collect::<Vec<_>>()
    );
    assert!(
        linked_vendor.join("precious").is_file(),
        "gc followed a symlink out of the state root"
    );
    assert!(beside_vendor.join("precious").is_file());
    assert!(
        report
            .entries
            .iter()
            .all(|entry| entry.attempt_id != beside_id)
    );
    let linked = entry(&report, &linked_id);
    assert_eq!(linked.action, "skipped", "{}", linked.reason);
    assert!(linked.reason.contains("symlink"), "{}", linked.reason);
}

/// The same rule one level up: an `attempts` directory that is a symlink is
/// not the registered state root's, and `gc` refuses it (§6.2, §6.4: exit 1)
/// rather than cleaning what it points to.
#[test]
fn j4_c03_a_symlinked_attempts_directory_is_refused() {
    let fixture = Fixture::new();
    std::fs::remove_dir(fixture.data.join("attempts")).unwrap();
    let elsewhere = fixture.outside.join("attempts");
    private_dir(&elsewhere);
    let id = fresh_id();
    let vendor = cleanable_attempt(&elsewhere, &id);
    std::os::unix::fs::symlink(&elsewhere, fixture.data.join("attempts")).unwrap();
    let error = match fixture.gc(false) {
        Ok(report) => panic!(
            "gc scanned through a symlinked attempts directory: {:?}",
            report
                .entries
                .iter()
                .map(|e| (&e.attempt_id, &e.action))
                .collect::<Vec<_>>()
        ),
        Err(error) => error,
    };
    assert_eq!(error.code.as_str(), "unsafe_state_path", "{error}");
    assert!(vendor.join("precious").is_file());
}

// ===========================================================================
// S7: the entry bound is per invocation, the listing included
// ===========================================================================

/// §14.2 "Cleanup is bounded per pass (initially 100,000 entries ...)", with
/// S7: the bound is per `gc` invocation and includes the attempts listing. The
/// test seam `OURO_JAIL_TEST_GC_MAX_ENTRIES` shrinks it (S9: shrink-only,
/// recorded when set). With a bound of 4 and 7 roots, one invocation reads at
/// most 4 names, says the scan did not complete, and exits 1 (§6.4: not a
/// completed scan).
#[test]
fn j4_c03_the_listing_counts_against_the_per_invocation_bound() {
    let fixture = Fixture::new();
    for _ in 0..7 {
        fixture.root_of(&fresh_id());
    }
    let output = fixture.binary(
        &["gc", "--json", "--dry-run"],
        &[("OURO_JAIL_TEST_GC_MAX_ENTRIES", "4")],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("no JSON report ({error}): {stderr}"));
    assert_eq!(output.status.code(), Some(1), "{report:#} {stderr}");
    let entries = report["entries"].as_array().unwrap();
    assert!(
        entries.len() <= 4,
        "{} entries listed: {report:#}",
        entries.len()
    );
    assert_eq!(report["budget"]["max_entries"], 4, "{report:#}");
    assert_eq!(report["budget"]["exhausted"], true, "{report:#}");
    assert_eq!(report["budget"]["listing_complete"], false, "{report:#}");
    assert!(
        report["budget"]["charged"].as_u64().unwrap() <= 4,
        "{report:#}"
    );
    assert_eq!(
        report["test_seams"]["OURO_JAIL_TEST_GC_MAX_ENTRIES"], "4",
        "S9: a seam in use is recorded: {report:#}"
    );
    // A seam can only shrink the bound.
    let output = fixture.binary(
        &["gc", "--json", "--dry-run"],
        &[("OURO_JAIL_TEST_GC_MAX_ENTRIES", "999999999")],
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["budget"]["max_entries"], 100_000, "{report:#}");
    assert_eq!(output.status.code(), Some(0), "{report:#}");
    // Unset, nothing is recorded.
    let output = fixture.binary(&["gc", "--json", "--dry-run"], &[]);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["test_seams"]
            .as_object()
            .is_none_or(|seams| seams.is_empty()),
        "{report:#}"
    );
}

// ===========================================================================
// Decisions that depend on the host: a scripted host records every call
// ===========================================================================

mod scripted {
    use super::*;
    use ouro_jail::gc::{
        self, Host, HostIdentity, LeafProbe, LeafRecord, Liveness, Options, OwnerRecord,
    };

    /// A host whose answers the test chooses and whose every call is logged.
    pub struct Scripted {
        pub boot: Option<String>,
        pub owner: Liveness,
        pub leaf: LeafProbe,
        pub terminate: Result<(), String>,
        pub calls: Mutex<Vec<String>>,
    }

    impl Scripted {
        pub fn new(owner: Liveness, leaf: LeafProbe) -> Scripted {
            Scripted {
                boot: Some(HOST_BOOT.to_owned()),
                owner,
                leaf,
                terminate: Ok(()),
                calls: Mutex::new(Vec::new()),
            }
        }
        pub fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn log(&self, call: String) {
            self.calls.lock().unwrap().push(call);
        }
    }

    impl Host for Scripted {
        fn identity(&self) -> HostIdentity {
            HostIdentity {
                os: Os::Linux,
                arch: SIM_ARCH.to_owned(),
                boot_id: self.boot.clone(),
            }
        }
        fn owner(&self, owner: &OwnerRecord) -> Liveness {
            self.log(format!("owner {}", owner.pid));
            self.owner.clone()
        }
        fn probe_leaf(&self, leaf: &LeafRecord) -> LeafProbe {
            self.log(format!("probe_leaf {}", leaf.inode));
            self.leaf.clone()
        }
        fn terminate_leaf(&self, leaf: &LeafRecord, _: Duration) -> Result<(), String> {
            self.log(format!("terminate_leaf {}", leaf.inode));
            self.terminate.clone()
        }
        fn remove_leaf(&self, leaf: &LeafRecord, _: &mut usize) -> Result<(), String> {
            self.log(format!("remove_leaf {}", leaf.inode));
            Ok(())
        }
    }

    fn run(fixture: &Fixture, host: &Scripted, dry_run: bool) -> gc::Report {
        gc::gc_with(
            &fixture.context(),
            &gc_args(dry_run),
            host,
            Options::DEFAULT,
        )
        .unwrap_or_else(|error| panic!("gc scans: {error}"))
    }

    fn only<'a>(report: &'a gc::Report, id: &str) -> &'a gc::Entry {
        report
            .entries
            .iter()
            .find(|entry| entry.attempt_id == id)
            .unwrap_or_else(|| panic!("no entry for {id}"))
    }

    fn cgroup_calls(calls: &[String]) -> Vec<&String> {
        calls.iter().filter(|call| call.contains("leaf")).collect()
    }

    /// A `none` attempt whose supervisor died after release, recorded in
    /// `boot`, with its leaf in the receipt.
    fn orphan(fixture: &Fixture, boot: &str) -> (String, AttemptDir) {
        let id = fresh_id();
        let dir = fixture.root_of(&id);
        free_lock(&dir);
        claim_dead_owner(&dir, boot);
        enforced_receipt_with_leaf(&dir, boot, &gc_leaf::sample());
        (id, dir)
    }

    /// §14.2: "After host reboot, the old processes cannot be alive, but any
    /// reused cgroup path must not be treated as the original resource." An
    /// attempt recorded in another boot never leads to any cgroup call, not
    /// even a probe, and its owner is not asked about either: its pid names
    /// nothing in this boot.
    #[test]
    fn j4_c03_a_different_boot_never_leads_to_any_cgroup_action() {
        let fixture = Fixture::new();
        let (id, dir) = orphan(&fixture, OTHER_BOOT);
        for dry_run in [true, false] {
            // Answers that would kill the leaf if they were ever asked for.
            let host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: true });
            let report = run(&fixture, &host, dry_run);
            let entry = only(&report, &id);
            assert_eq!(host.calls(), Vec::<String>::new(), "dry_run={dry_run}");
            let cgroup = entry.cgroup.as_deref().unwrap_or_default();
            assert!(cgroup.contains("another boot"), "{cgroup}");
            assert!(
                entry
                    .owner
                    .as_deref()
                    .is_some_and(|owner| owner.contains("another boot")),
                "{:?}",
                entry.owner
            );
            assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
            let state = read_json(&dir.state_path());
            assert!(
                state["gc_actions"]
                    .as_array()
                    .is_none_or(|actions| actions.iter().all(|action| !action["action"]
                        .as_str()
                        .unwrap_or("")
                        .contains("cgroup")
                        && !action["action"].as_str().unwrap_or("").contains("orphan"))),
                "{state:#}"
            );
        }
    }

    /// The same boot, a free lease, and a recorded owner that is still alive:
    /// something replaced or never held the lock, but the supervisor is there.
    /// It is the only killer while it lives (north star §4.2), so gc retains
    /// everything and asks nothing about the leaf.
    #[test]
    fn j4_c03_an_owner_alive_without_the_lease_is_retained() {
        let fixture = Fixture::new();
        let (id, dir) = orphan(&fixture, HOST_BOOT);
        let vendor = vendor_state_pending(&dir);
        for dry_run in [true, false] {
            let before = picture(&fixture.data);
            let host = Scripted::new(Liveness::Alive, LeafProbe::Identified { populated: true });
            let report = run(&fixture, &host, dry_run);
            let entry = only(&report, &id);
            assert_eq!(entry.action, "retained", "{}", entry.reason);
            assert!(entry.reason.contains("alive"), "{}", entry.reason);
            assert_eq!(cgroup_calls(&host.calls()), Vec::<&String>::new());
            assert_eq!(picture(&fixture.data), before, "dry_run={dry_run}");
            assert!(vendor.join("precious").is_file());
        }
    }

    /// Same boot, dead owner, a positively identified populated leaf: the
    /// orphan is terminated, verified empty and removed, in that order, and
    /// jail state records it before and after (S6); the supervisor's receipt
    /// is never rewritten. The dry run only probes.
    #[test]
    fn j4_c03_a_populated_orphan_of_this_boot_is_terminated_verified_and_removed() {
        let fixture = Fixture::new();
        let (id, dir) = orphan(&fixture, HOST_BOOT);
        let receipt = std::fs::read(dir.receipt_path()).unwrap();

        let before = picture(&fixture.data);
        let host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: true });
        let report = run(&fixture, &host, true);
        let entry = only(&report, &id);
        assert_eq!(picture(&fixture.data), before, "a dry run changes nothing");
        assert_eq!(cgroup_calls(&host.calls()), ["probe_leaf 4242"]);
        assert_eq!(entry.cgroup.as_deref(), Some("would_terminate_orphan"));

        let host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: true });
        let report = run(&fixture, &host, false);
        let entry = only(&report, &id);
        assert_eq!(
            cgroup_calls(&host.calls()),
            ["probe_leaf 4242", "terminate_leaf 4242", "remove_leaf 4242"]
        );
        assert_eq!(
            entry.cgroup.as_deref(),
            Some("terminated_orphan_and_removed"),
            "{}",
            entry.reason
        );
        assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
        let actions: Vec<String> = read_json(&dir.state_path())["gc_actions"]
            .as_array()
            .expect("S6: gc records what it did in jail state")
            .iter()
            .map(|action| action["action"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            actions,
            [
                "gc_terminating_orphan",
                "gc_terminated_orphan",
                "gc_removed_cgroup"
            ]
        );
        assert_eq!(
            std::fs::read(dir.receipt_path()).unwrap(),
            receipt,
            "S6: the supervisor's receipt is never rewritten"
        );
        assert_eq!(entry.recorded, actions);
    }

    /// "Verify emptiness before deleting state" (§14.2): when the kill cannot
    /// be verified (the leaf stays populated past its budget), the leaf is not
    /// removed, managed scratch stays, only the intent is recorded, and the
    /// cleanup is incomplete (§6.4: exit 1).
    #[test]
    fn j4_c03_an_unverified_termination_deletes_nothing() {
        let fixture = Fixture::new();
        let (id, dir) = orphan(&fixture, HOST_BOOT);
        let scratch = managed_scratch(&dir, 3);
        let mut host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: true });
        host.terminate = Err("still populated 5000 ms after cgroup.kill".to_owned());
        let report = run(&fixture, &host, false);
        let entry = only(&report, &id);
        assert_eq!(
            cgroup_calls(&host.calls()),
            ["probe_leaf 4242", "terminate_leaf 4242"],
            "nothing is removed after an unverified kill"
        );
        assert_eq!(entry.action, "pending", "{}", entry.reason);
        assert!(
            entry
                .cgroup
                .as_deref()
                .is_some_and(|cgroup| cgroup.starts_with("failed")),
            "{:?}",
            entry.cgroup
        );
        assert!(
            scratch.join("f0").is_file(),
            "scratch removed after an unverified end"
        );
        assert!(report.incomplete.iter().any(|item| item.contains(&id)));
        let actions: Vec<Value> = read_json(&dir.state_path())["gc_actions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            actions
                .iter()
                .map(|action| action["action"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["gc_terminating_orphan"],
            "the intent, and nothing gc could not verify"
        );
    }

    /// Unverifiable identities are retained (§14.2): an owner whose liveness
    /// cannot be read leaves the leaf unprobed, and a leaf that is gone,
    /// replaced or unverifiable is never terminated or removed.
    #[test]
    fn j4_c03_an_unverified_owner_or_leaf_is_never_acted_on() {
        let cases = [
            (
                Liveness::Unknown("no /proc here".to_owned()),
                LeafProbe::Identified { populated: true },
                0,
            ),
            (Liveness::Gone, LeafProbe::Absent, 1),
            (Liveness::Reused, LeafProbe::Replaced, 1),
            (
                Liveness::Exited,
                LeafProbe::Unverifiable("not cgroup2".to_owned()),
                1,
            ),
        ];
        for (owner, leaf, probes) in cases {
            let label = format!("{owner:?}/{leaf:?}");
            let fixture = Fixture::new();
            let (id, dir) = orphan(&fixture, HOST_BOOT);
            let scratch = managed_scratch(&dir, 2);
            let host = Scripted::new(owner, leaf);
            let report = run(&fixture, &host, false);
            let entry = only(&report, &id);
            let calls = host.calls();
            let cgroup = cgroup_calls(&calls);
            assert_eq!(cgroup.len(), probes, "{label}: {calls:?}");
            assert!(
                cgroup.iter().all(|call| call.starts_with("probe_leaf")),
                "{label}: {calls:?}"
            );
            assert!(scratch.join("f0").is_file(), "{label}: tree end unverified");
            assert!(
                read_json(&dir.state_path())["gc_actions"].is_null(),
                "{label}: nothing done, nothing recorded"
            );
            assert!(entry.cgroup.is_some(), "{label}: the report says why");
        }
    }

    /// S7 across removals: with a bound of 13 entries, three attempts from a
    /// previous boot (whose tree ended with that boot) each hold 6 scratch
    /// files. The listing costs 3, and what is left covers one removal at
    /// most; the rest stay pending for the next pass and `gc` exits 1.
    #[test]
    fn j4_c03_the_entry_bound_holds_across_removals_in_one_invocation() {
        let fixture = Fixture::new();
        let mut scratches = Vec::new();
        for _ in 0..3 {
            let (_, dir) = orphan(&fixture, OTHER_BOOT);
            scratches.push(managed_scratch(&dir, 6));
        }
        let host = Scripted::new(Liveness::Gone, LeafProbe::Absent);
        let report = gc::gc_with(
            &fixture.context(),
            &gc_args(false),
            &host,
            Options {
                max_entries: 13,
                ..Options::DEFAULT
            },
        )
        .unwrap();
        let removed = scratches.iter().filter(|scratch| !scratch.exists()).count();
        assert!(removed <= 1, "{removed} scratch trees removed in one pass");
        assert!(report.budget.charged <= 13, "{:?}", report.budget);
        assert!(report.budget.exhausted, "{:?}", report.budget);
        assert!(!report.incomplete.is_empty(), "work remains: exit 1");
        // And the next passes finish it.
        for _ in 0..4 {
            let host = Scripted::new(Liveness::Gone, LeafProbe::Absent);
            gc::gc_with(
                &fixture.context(),
                &gc_args(false),
                &host,
                Options {
                    max_entries: 13,
                    ..Options::DEFAULT
                },
            )
            .unwrap();
        }
        assert!(scratches.iter().all(|scratch| !scratch.exists()));
    }
}
