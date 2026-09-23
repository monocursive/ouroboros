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

/// N7: the execution leaf as the supervisor registers it in jail state: its
/// path before `mkdir`, then its device and inode (`identified`).
fn register_leaf(dir: &AttemptDir, leaf: &gc_leaf::Leaf, identified: bool) {
    let mut state = read_json(&dir.state_path());
    state["execution_cgroup"] = json!({
        "path": leaf.path,
        "device": identified.then_some(leaf.device),
        "inode": identified.then_some(leaf.inode),
    });
    json_file(&dir.state_path(), &state);
}

/// The execution leaf of the attempt at `dir`, named for it as the platform
/// names it (J4 wave 3, G2: `ouro-<attempt id>.leaf`).
fn leaf_of(dir: &AttemptDir) -> gc_leaf::Leaf {
    gc_leaf::Leaf {
        path: format!(
            "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/ouro-{}.leaf",
            dir.root().file_name().unwrap().to_str().unwrap()
        ),
        ..gc_leaf::sample()
    }
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
        fn probe_named_leaf(&self, path: &Path) -> LeafProbe {
            self.log(format!("probe_named_leaf {}", path.display()));
            self.leaf.clone()
        }
        fn remove_named_leaf(&self, path: &Path, _: &mut usize) -> Result<(u64, u64), String> {
            self.log(format!("remove_named_leaf {}", path.display()));
            Ok((30, 5151))
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
    /// `boot`, with its leaf registered in jail state (N7) and named in the
    /// receipt.
    fn orphan(fixture: &Fixture, boot: &str) -> (String, AttemptDir) {
        let id = fresh_id();
        let dir = fixture.root_of(&id);
        free_lock(&dir);
        claim_dead_owner(&dir, boot);
        let leaf = leaf_of(&dir);
        register_leaf(&dir, &leaf, true);
        enforced_receipt_with_leaf(&dir, boot, &leaf);
        (id, dir)
    }

    // -----------------------------------------------------------------------
    // N7: the leaf is read from jail state, never from the receipt alone
    // -----------------------------------------------------------------------

    /// N7 (J4 wave 2). A supervisor that dies after creating its leaf and
    /// before its `prepared` receipt leaves jail state naming the leaf and
    /// no receipt at all. gc reads the leaf from jail state, so the
    /// populated orphan of this boot is terminated, verified and removed.
    #[test]
    fn j4_n7_gc_finds_a_leaf_jail_state_registers_without_any_receipt() {
        let fixture = Fixture::new();
        let id = fresh_id();
        let dir = fixture.root_of(&id);
        free_lock(&dir);
        claim_dead_owner(&dir, HOST_BOOT);
        register_leaf(&dir, &leaf_of(&dir), true);
        assert!(!dir.receipt_path().exists());
        let host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: true });
        let report = run(&fixture, &host, false);
        let entry = only(&report, &id);
        assert_eq!(
            cgroup_calls(&host.calls()),
            ["probe_leaf 4242", "terminate_leaf 4242", "remove_leaf 4242"],
            "{entry:?}"
        );
        assert_eq!(
            entry.cgroup.as_deref(),
            Some("terminated_orphan_and_removed"),
            "{entry:?}"
        );
        assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
    }

    /// N7: the receipt is not a registration. A leaf only a receipt names
    /// (jail state registers none) is never probed, killed or removed; the
    /// report says it is not recorded.
    #[test]
    fn j4_n7_a_leaf_only_the_receipt_names_is_never_acted_on() {
        let fixture = Fixture::new();
        let id = fresh_id();
        let dir = fixture.root_of(&id);
        free_lock(&dir);
        claim_dead_owner(&dir, HOST_BOOT);
        enforced_receipt_with_leaf(&dir, HOST_BOOT, &leaf_of(&dir));
        let host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: true });
        let report = run(&fixture, &host, false);
        let entry = only(&report, &id);
        assert_eq!(cgroup_calls(&host.calls()), Vec::<&String>::new());
        assert!(
            entry.cgroup.as_deref().is_some_and(
                |cgroup| cgroup.starts_with("not_recorded") && cgroup.contains("jail state")
            ),
            "{entry:?}"
        );
    }

    /// N7: a supervisor that died between naming its leaf (P15) and
    /// recording its identity (P16) placed nothing in it. gc removes such a
    /// leaf when it is empty, by its name and place alone, and records the
    /// identity it removed; one that is populated (by something else) or
    /// cannot be verified is retained, and nothing registered by name only
    /// is ever killed.
    #[test]
    fn j4_n7_a_leaf_named_only_is_removed_when_empty_and_never_killed() {
        let named = |fixture: &Fixture| {
            let id = fresh_id();
            let dir = fixture.root_of(&id);
            free_lock(&dir);
            claim_dead_owner(&dir, HOST_BOOT);
            register_leaf(&dir, &leaf_of(&dir), false);
            (id, dir)
        };

        let fixture = Fixture::new();
        let (id, dir) = named(&fixture);
        let path = leaf_of(&dir).path;
        let host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: false });
        let report = run(&fixture, &host, true);
        assert_eq!(
            only(&report, &id).cgroup.as_deref(),
            Some("would_remove"),
            "{:?}",
            only(&report, &id)
        );
        assert_eq!(
            cgroup_calls(&host.calls()),
            [&format!("probe_named_leaf {path}")]
        );
        let report = run(&fixture, &host, false);
        let entry = only(&report, &id);
        assert_eq!(entry.cgroup.as_deref(), Some("removed"), "{entry:?}");
        let actions = read_json(&dir.state_path())["gc_actions"].clone();
        // J4 wave 3 (G3): the intent, by name, before the rmdir; then the
        // identity it removed.
        assert_eq!(actions[0]["action"], "gc_removing_cgroup", "{actions:#}");
        assert_eq!(actions[0]["registered"], "name_only", "{actions:#}");
        assert_eq!(
            actions[0]["execution_cgroup"]["inode"],
            Value::Null,
            "{actions:#}"
        );
        assert_eq!(actions[1]["action"], "gc_removed_cgroup", "{actions:#}");
        assert_eq!(actions[1]["registered"], "name_only", "{actions:#}");
        assert_eq!(actions[1]["execution_cgroup"]["inode"], 5151, "{actions:#}");
        // The next pass knows it is gone: nothing was left (J4 wave 3, G4).
        let host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: false });
        let report = run(&fixture, &host, false);
        assert!(
            only(&report, &id).reason.starts_with("finished"),
            "{:?}",
            only(&report, &id)
        );
        assert_eq!(host.calls(), Vec::<String>::new());

        for probe in [
            LeafProbe::Identified { populated: true },
            LeafProbe::Unverifiable("not cgroup2".to_owned()),
            LeafProbe::Absent,
        ] {
            let fixture = Fixture::new();
            let (id, dir) = named(&fixture);
            let path = leaf_of(&dir).path;
            let host = Scripted::new(Liveness::Gone, probe.clone());
            let report = run(&fixture, &host, false);
            let entry = only(&report, &id);
            assert_eq!(
                cgroup_calls(&host.calls()),
                [&format!("probe_named_leaf {path}")],
                "{probe:?}: only a probe"
            );
            assert!(entry.cgroup.is_some(), "{probe:?}: the report says why");
            assert!(report.incomplete.is_empty(), "{probe:?}");
            // Nothing done, nothing recorded; a leaf that never existed
            // leaves nothing for a later pass (J4 wave 3, G4).
            let actions = read_json(&dir.state_path())["gc_actions"].clone();
            let expected = if probe == LeafProbe::Absent {
                json!([{"action": "gc_finished", "at": actions[0]["at"]}])
            } else {
                Value::Null
            };
            assert_eq!(
                actions, expected,
                "{probe:?}: nothing done, nothing recorded"
            );
        }
    }

    // -----------------------------------------------------------------------
    // J4 wave 2 (d): a tree gc verified dead permits vendor-state cleanup
    // -----------------------------------------------------------------------

    /// §14.2, J4 wave 2: vendor state waits for proof that no tree can use
    /// it. A supervisor that died after release left an `enforced` receipt
    /// (tree unverified), so its receipt proves nothing; but when gc itself
    /// ends the registered leaf's tree and verifies the leaf empty
    /// (`gc_terminated_orphan`, `gc_removed_cgroup`), that is the proof, and
    /// the pending cleanup completes in the same pass. An unverified kill
    /// proves nothing and the vendor state stays.
    #[test]
    fn j4_w2s_a_tree_gc_verified_dead_permits_the_vendor_state_cleanup() {
        for (terminate, cleaned) in [(Ok(()), true), (Err("still populated".to_owned()), false)] {
            let label = format!("terminate {terminate:?}");
            let fixture = Fixture::new();
            let (id, dir) = orphan(&fixture, HOST_BOOT);
            let vendor = vendor_state_pending(&dir);
            let mut host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: true });
            host.terminate = terminate;
            let report = run(&fixture, &host, false);
            let entry = only(&report, &id);
            assert_eq!(
                !vendor.exists(),
                cleaned,
                "{label}: {} / {}",
                entry.action,
                entry.reason
            );
            let state = read_json(&dir.state_path());
            assert_eq!(
                state["state_cleanup"] == "complete",
                cleaned,
                "{label}: {state:#}"
            );
        }
    }

    /// The same proof with no receipt at all (the supervisor died before its
    /// `prepared` receipt, N7): jail state alone records the completion.
    /// And a gc record for some other leaf proves nothing about this one.
    #[test]
    fn j4_w2s_only_gcs_record_of_the_registered_leaf_permits_the_cleanup() {
        let fixture = Fixture::new();
        let id = fresh_id();
        let dir = fixture.root_of(&id);
        free_lock(&dir);
        claim_dead_owner(&dir, HOST_BOOT);
        register_leaf(&dir, &leaf_of(&dir), true);
        let vendor = vendor_state_pending(&dir);
        let host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: false });
        let report = run(&fixture, &host, false);
        let entry = only(&report, &id);
        assert!(!vendor.exists(), "{} / {}", entry.action, entry.reason);
        assert_eq!(read_json(&dir.state_path())["state_cleanup"], "complete");
        assert!(!dir.receipt_path().exists(), "gc writes no receipt");

        let fixture = Fixture::new();
        let (id, dir) = orphan(&fixture, HOST_BOOT);
        let vendor = vendor_state_pending(&dir);
        let mut other = leaf_of(&dir);
        other.inode += 7;
        let mut state = read_json(&dir.state_path());
        state["gc_actions"] = json!([{
            "action": "gc_removed_cgroup",
            "at": "2026-09-23T00:00:00Z",
            "execution_cgroup": {"path": other.path, "device": other.device, "inode": other.inode},
        }]);
        json_file(&dir.state_path(), &state);
        let host = Scripted::new(Liveness::Gone, LeafProbe::Unverifiable("x".to_owned()));
        let report = run(&fixture, &host, false);
        let entry = only(&report, &id);
        assert!(
            vendor.join("precious").is_file(),
            "another leaf's record permitted the cleanup: {} / {}",
            entry.action,
            entry.reason
        );
    }

    /// J4 wave 2: leftover temporary files are removed only for an owner gc
    /// established dead. Alive: the attempt is retained whole and nothing is
    /// even listed. Unknown liveness: listed, reported, kept.
    #[test]
    fn j4_w2s_leftover_temp_files_stay_unless_the_owner_is_dead() {
        for (owner, listed) in [
            (Liveness::Alive, false),
            (Liveness::Unknown("no /proc here".to_owned()), true),
        ] {
            let fixture = Fixture::new();
            let (id, dir) = orphan(&fixture, HOST_BOOT);
            let temp = leftover(&dir, "jail.json");
            let host = Scripted::new(owner.clone(), LeafProbe::Absent);
            let report = run(&fixture, &host, false);
            let entry = only(&report, &id);
            assert!(temp.is_file(), "{owner:?}: removed");
            assert_eq!(
                !entry.leftover_temp_files.is_empty(),
                listed,
                "{owner:?}: {entry:?}"
            );
            if listed {
                assert!(
                    entry
                        .temp_files
                        .as_deref()
                        .is_some_and(|text| text.starts_with("retained")),
                    "{owner:?}: {entry:?}"
                );
            }
        }
    }

    /// N7: jail state and the receipt naming different leaves disagree, and
    /// records that disagree are retained (§14.2), whichever is right.
    #[test]
    fn j4_n7_state_and_receipt_naming_different_leaves_are_retained() {
        let fixture = Fixture::new();
        let (id, dir) = orphan(&fixture, HOST_BOOT);
        let mut other = leaf_of(&dir);
        other.inode += 1;
        register_leaf(&dir, &other, true);
        let host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: true });
        let report = run(&fixture, &host, false);
        let entry = only(&report, &id);
        assert_eq!(cgroup_calls(&host.calls()), Vec::<&String>::new());
        assert!(
            entry.cgroup.as_deref().is_some_and(
                |cgroup| cgroup.starts_with("retained") && cgroup.contains("different")
            ),
            "{entry:?}"
        );
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
                "gc_removing_cgroup",
                "gc_removed_cgroup",
                "gc_finished"
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

// ===========================================================================
// N7: a leaf registered by name only
// ===========================================================================

/// N7: a supervisor that dies between the leaf's name (P15) and its
/// identity (P16) leaves a registration with a path and null device and
/// inode. That is a shape the supervisor writes, not corrupt state: gc
/// reports and retains what it cannot identify (here, a host without the
/// mechanism) and exits 0.
#[test]
fn j4_n7_a_leaf_registered_by_name_only_is_not_corrupt_state() {
    let fixture = Fixture::new();
    let id = fresh_id();
    let dir = fixture.root_of(&id);
    free_lock(&dir);
    claim(&dir, "linux", SIM_ARCH, Some((dead_pid(), HOST_BOOT, 1)));
    register_leaf(&dir, &leaf_of(&dir), false);
    let report = fixture.gc(false).expect("gc scans");
    let entry = entry(&report, &id);
    assert!(
        report.incomplete.is_empty(),
        "a name-only registration is not a failed state access: {:?} ({})",
        report.incomplete,
        entry.reason
    );
    assert!(!entry.reason.contains("corrupt"), "{}", entry.reason);
}

// ===========================================================================
// J4 wave 2: leftover temporary files and the per-invocation bound
// ===========================================================================

/// A temporary file of the shape a durable replacement of `record` leaves
/// when the process dies mid-write (`.<record>.<uuid>.tmp`).
fn leftover(dir: &AttemptDir, record: &str) -> PathBuf {
    let path = dir.root().join(format!(".{record}.{}.tmp", uuid_like()));
    private_file(&path, b"{\"partial\": ");
    path
}

fn uuid_like() -> String {
    AttemptId::generate()
        .as_str()
        .trim_start_matches("att_")
        .to_owned()
}

/// The claim of an attempt this very host's binary made (its OS and
/// architecture), recorded in a boot that is not this one: on Linux the owner
/// is then dead; on macOS no boot can be read, so the owner stays unknown.
fn host_claim(dir: &AttemptDir) {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else {
        "macos"
    };
    claim(
        dir,
        os,
        std::env::consts::ARCH,
        Some((dead_pid(), OTHER_BOOT, 1)),
    );
}

/// §7: "a crash can leave one (`.<name>.<id>.tmp`), which never replaced
/// anything". J4 wave 2: gc removes the temporary files a crash left in an
/// attempt root whose lease it holds, only when the attempt's owner is dead
/// (here recorded in another boot), and records what it removed (S6); a dry
/// run removes nothing, and a name of another shape is kept.
#[test]
fn j4_w2s_gc_removes_a_dead_attempts_leftover_temp_files() {
    let fixture = Fixture::new();
    let id = fresh_id();
    let dir = fixture.root_of(&id);
    free_lock(&dir);
    claim(&dir, "linux", SIM_ARCH, Some((dead_pid(), OTHER_BOOT, 1)));
    let ours = [
        leftover(&dir, "jail.json"),
        leftover(&dir, "jail-state.json"),
    ];
    let foreign = dir.root().join(".planted.tmp");
    private_file(&foreign, b"x");

    fixture.gc(true).expect("gc scans");
    assert!(
        ours.iter().all(|path| path.is_file()),
        "a dry run removed one"
    );

    let report = fixture.gc(false).expect("gc scans");
    assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
    assert!(
        ours.iter().all(|path| !path.exists()),
        "{:?}",
        entry(&report, &id).reason
    );
    assert!(foreign.is_file(), "a name of another shape was removed");
    let actions = read_json(&dir.state_path())["gc_actions"].clone();
    let removal = actions
        .as_array()
        .and_then(|actions| {
            actions
                .iter()
                .find(|action| action["action"] == "gc_removed_temp_files")
        })
        .unwrap_or_else(|| panic!("S6: gc records what it removed: {actions:#}"));
    let mut removed: Vec<String> = ours
        .iter()
        .map(|path| path.file_name().unwrap().to_str().unwrap().to_owned())
        .collect();
    removed.sort();
    assert_eq!(removal["names"], json!(removed), "{actions:#}");
}

/// The report (`gc --json`, the real binary): every temporary file found in
/// a leased attempt root is listed, and `temp_files` says what became of
/// them — removed where the owner is dead, kept where it is not known to be.
#[test]
fn j4_w2s_gc_reports_leftover_temp_files() {
    let fixture = Fixture::new();
    let id = fresh_id();
    let dir = fixture.root_of(&id);
    free_lock(&dir);
    host_claim(&dir);
    let mut names = [leftover(&dir, "jail.json"), leftover(&dir, "policy.json")]
        .iter()
        .map(|path| path.file_name().unwrap().to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    names.sort();
    for (args, linux) in [
        (&["gc", "--json", "--dry-run"][..], "would_remove"),
        (&["gc", "--json"][..], "removed"),
    ] {
        let output = fixture.binary(args, &[]);
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(0), "{args:?}: {report:#}");
        let entry = report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["attempt_id"] == id.as_str())
            .unwrap()
            .clone();
        assert_eq!(
            entry["leftover_temp_files"],
            json!(names),
            "{args:?}: {entry:#}"
        );
        let temp_files = entry["temp_files"].as_str().unwrap_or_default();
        if cfg!(target_os = "linux") {
            assert!(temp_files.starts_with(linux), "{args:?}: {entry:#}");
        } else {
            assert!(temp_files.starts_with("retained"), "{args:?}: {entry:#}");
        }
    }
}

/// S7 (J4 wave 2): the J3 resumption of a pending vendor-state cleanup used
/// its own 100,000-entry bound, outside gc's per-invocation one. With a
/// bound of 10 and 30 files of vendor state, one invocation removes at most
/// what the bound leaves, reports the cleanup pending (exit 1), and the next
/// invocations finish it.
#[test]
fn j4_w2s_vendor_state_cleanup_is_charged_to_the_per_invocation_bound() {
    let fixture = Fixture::new();
    let id = fresh_id();
    let dir = fixture.root_of(&id);
    free_lock(&dir);
    host_claim(&dir);
    let vendor = vendor_state_pending(&dir);
    for index in 0..30 {
        private_file(&vendor.join(format!("f{index}")), b"vendor");
    }
    settled_receipt(&dir, OTHER_BOOT);
    let bound = [("OURO_JAIL_TEST_GC_MAX_ENTRIES", "10")];
    let output = fixture.binary(&["gc", "--json"], &bound);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let left = std::fs::read_dir(&vendor).map_or(0, |listing| listing.count());
    assert!(
        vendor.exists() && left > 0,
        "one invocation with a bound of 10 removed all 31 files: {report:#}"
    );
    assert!(
        report["budget"]["charged"].as_u64().unwrap() <= 10,
        "{report:#}"
    );
    assert_eq!(report["budget"]["exhausted"], true, "{report:#}");
    assert_eq!(output.status.code(), Some(1), "pending: {report:#}");
    for _ in 0..6 {
        fixture.binary(&["gc", "--json"], &bound);
    }
    assert!(!vendor.exists(), "the next invocations finish it");
    assert_eq!(read_json(&dir.state_path())["state_cleanup"], "complete");
}

// ===========================================================================
// J4 wave 3: the gc review's findings (G1–G6), each red on 191bdb7b first
// ===========================================================================

mod w3 {
    use super::*;
    use std::sync::Arc;

    use ouro_jail::gc::{
        self, Host, HostIdentity, LeafProbe, LeafRecord, Liveness, Options, OwnerRecord,
    };

    /// The execution leaf of the attempt named `id`, named for it as the
    /// platform names it (G2: `ouro-<attempt id>.leaf`).
    pub fn own_leaf(id: &str) -> gc_leaf::Leaf {
        gc_leaf::Leaf {
            path: format!(
                "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/ouro-{id}.leaf"
            ),
            device: 30,
            inode: 4242,
        }
    }

    /// What is at a leaf's path on the simulated host.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Cgroup {
        Populated,
        Empty,
        Gone,
    }

    /// A host whose one leaf behaves as a real one does: a kill that works
    /// empties it, a removal of an empty one makes it gone, and what the
    /// next pass probes is what the last one left. The owner is dead. It
    /// also notes, at each `rmdir`, whether jail state already recorded the
    /// removal's intent (G3).
    pub struct Stateful {
        pub cgroup: Mutex<Cgroup>,
        pub kill_works: bool,
        pub calls: Mutex<Vec<String>>,
        pub intent_before_rmdir: Mutex<Vec<bool>>,
        pub state_path: PathBuf,
    }

    impl Stateful {
        pub fn new(dir: &AttemptDir, cgroup: Cgroup) -> Stateful {
            Stateful {
                cgroup: Mutex::new(cgroup),
                kill_works: true,
                calls: Mutex::new(Vec::new()),
                intent_before_rmdir: Mutex::new(Vec::new()),
                state_path: dir.state_path(),
            }
        }
        pub fn now(&self) -> Cgroup {
            *self.cgroup.lock().unwrap()
        }
        fn log(&self, call: &str, path: &Path) {
            self.calls.lock().unwrap().push(format!(
                "{call} {}",
                path.file_name().unwrap().to_string_lossy()
            ));
        }
        fn intent_recorded(&self, path: &Path) -> bool {
            let state = read_json(&self.state_path);
            state["gc_actions"].as_array().is_some_and(|actions| {
                actions.iter().any(|action| {
                    action["action"] == "gc_removing_cgroup"
                        && action["execution_cgroup"]["path"] == json!(path)
                })
            })
        }
        fn probe(&self) -> LeafProbe {
            match self.now() {
                Cgroup::Populated => LeafProbe::Identified { populated: true },
                Cgroup::Empty => LeafProbe::Identified { populated: false },
                Cgroup::Gone => LeafProbe::Absent,
            }
        }
        fn rmdir(&self, path: &Path) -> Result<(), String> {
            match self.now() {
                Cgroup::Populated => Err("populated; an occupied cgroup is never removed".into()),
                Cgroup::Gone => Err("the recorded leaf no longer exists".into()),
                Cgroup::Empty => {
                    let first = self.intent_recorded(path);
                    self.intent_before_rmdir.lock().unwrap().push(first);
                    *self.cgroup.lock().unwrap() = Cgroup::Gone;
                    Ok(())
                }
            }
        }
    }

    impl Host for Stateful {
        fn identity(&self) -> HostIdentity {
            HostIdentity {
                os: Os::Linux,
                arch: SIM_ARCH.to_owned(),
                boot_id: Some(HOST_BOOT.to_owned()),
            }
        }
        fn owner(&self, _: &OwnerRecord) -> Liveness {
            Liveness::Gone
        }
        fn probe_leaf(&self, leaf: &LeafRecord) -> LeafProbe {
            self.log("probe_leaf", &leaf.path);
            self.probe()
        }
        fn terminate_leaf(&self, leaf: &LeafRecord, _: Duration) -> Result<(), String> {
            self.log("terminate_leaf", &leaf.path);
            if !self.kill_works {
                return Err("still populated 5000 ms after cgroup.kill".into());
            }
            if self.now() == Cgroup::Populated {
                *self.cgroup.lock().unwrap() = Cgroup::Empty;
            }
            Ok(())
        }
        fn remove_leaf(&self, leaf: &LeafRecord, _: &mut usize) -> Result<(), String> {
            self.log("remove_leaf", &leaf.path);
            self.rmdir(&leaf.path)
        }
        fn probe_named_leaf(&self, path: &Path) -> LeafProbe {
            self.log("probe_named_leaf", path);
            self.probe()
        }
        fn remove_named_leaf(&self, path: &Path, _: &mut usize) -> Result<(u64, u64), String> {
            self.log("remove_named_leaf", path);
            self.rmdir(path).map(|()| (30, 4242))
        }
    }

    pub fn pass(fixture: &Fixture, host: &dyn Host, max_entries: usize) -> gc::Report {
        gc::gc_with(
            &fixture.context(),
            &gc_args(false),
            host,
            Options {
                max_entries,
                ..Options::DEFAULT
            },
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

    /// A claimed attempt of this boot whose owner is dead, with its own leaf
    /// registered (identity included) in jail state.
    fn dead_with_own_leaf(fixture: &Fixture) -> (String, AttemptDir, gc_leaf::Leaf) {
        let id = fresh_id();
        let dir = fixture.root_of(&id);
        free_lock(&dir);
        claim_dead_owner(&dir, HOST_BOOT);
        let leaf = own_leaf(&id);
        register_leaf(&dir, &leaf, true);
        (id, dir, leaf)
    }

    fn actions(dir: &AttemptDir) -> Vec<Value> {
        read_json(&dir.state_path())["gc_actions"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    // -----------------------------------------------------------------------
    // G1: gc never rewrites a receipt whose phase is not refused or settled
    // -----------------------------------------------------------------------

    /// G1 (gc review, HONESTY; live on the VPS before the fix). Since wave 2,
    /// gc's own verified kill permits the pending vendor-state cleanup even
    /// when the dead supervisor's last receipt is `enforced` or `prepared`;
    /// the resumption then set that receipt's `state_cleanup` to `complete`
    /// at the next revision, which the schema rejects ("enforced is not one
    /// of refused or settled"). S6: gc never rewrites such a receipt; the
    /// completion is recorded in jail state and gc's report only. The J3
    /// path is unchanged: a settled receipt that proves the tree's end still
    /// has its `state_cleanup` completed, at the next revision, and stays
    /// valid.
    #[test]
    fn j4_w3_g1_gc_never_rewrites_a_receipt_that_is_not_refused_or_settled() {
        for phase in ["enforced", "prepared"] {
            let fixture = Fixture::new();
            let (id, dir, leaf) = dead_with_own_leaf(&fixture);
            let mut receipt = enforced_receipt_with_leaf(&dir, HOST_BOOT, &leaf);
            receipt["phase"] = json!(phase);
            if phase == "prepared" {
                receipt["exec_observed"] = json!(false);
            }
            receipt["state_cleanup"] = json!("pending");
            json_file(&dir.receipt_path(), &receipt);
            common::check_receipt(&receipt)
                .unwrap_or_else(|error| panic!("{phase}: the receipt gc starts from: {error}"));
            let before = std::fs::read(dir.receipt_path()).unwrap();
            let vendor = vendor_state_pending(&dir);
            let host = Stateful::new(&dir, Cgroup::Populated);
            let report = pass(&fixture, &host, Options::DEFAULT.max_entries);
            let entry = only(&report, &id);
            assert!(
                !vendor.exists(),
                "{phase}: gc's verified kill permits the cleanup: {} / {}",
                entry.action,
                entry.reason
            );
            assert_eq!(
                read_json(&dir.state_path())["state_cleanup"],
                "complete",
                "{phase}: jail state records the completion"
            );
            let after = std::fs::read(dir.receipt_path()).unwrap();
            let value: Value = serde_json::from_slice(&after).unwrap();
            assert!(
                common::check_receipt(&value).is_ok(),
                "{phase}: gc left a schema-invalid receipt: {:?} (revision {}, state_cleanup {})",
                common::check_receipt(&value),
                value["revision"],
                value["state_cleanup"]
            );
            assert_eq!(
                after, before,
                "{phase}: S6, gc never rewrites a receipt that is not refused or settled"
            );
            assert!(
                entry.reason.contains("jail state")
                    && !entry.reason.contains("the receipt records"),
                "{phase}: the report says where the completion is recorded: {}",
                entry.reason
            );
            assert!(
                report.incomplete.is_empty(),
                "{phase}: {:?}",
                report.incomplete
            );
            // The next pass has nothing pending and still leaves the receipt.
            let report = pass(&fixture, &host, Options::DEFAULT.max_entries);
            assert!(
                report.incomplete.is_empty(),
                "{phase}: {:?}",
                report.incomplete
            );
            assert_eq!(
                std::fs::read(dir.receipt_path()).unwrap(),
                before,
                "{phase}"
            );
        }

        // J3 (C02), unchanged: a settled receipt proving the tree's end gets
        // its pending cleanup completed at the next revision, and is valid.
        let fixture = Fixture::new();
        let (_, dir, _) = dead_with_own_leaf(&fixture);
        let receipt = settled_receipt(&dir, HOST_BOOT);
        let vendor = vendor_state_pending(&dir);
        let host = Stateful::new(&dir, Cgroup::Gone);
        let report = pass(&fixture, &host, Options::DEFAULT.max_entries);
        assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
        assert!(!vendor.exists());
        let after = read_json(&dir.receipt_path());
        assert_eq!(after["state_cleanup"], "complete", "{after:#}");
        assert_eq!(
            after["revision"].as_u64(),
            receipt["revision"].as_u64().map(|revision| revision + 1)
        );
        common::check_receipt(&after).unwrap();
    }

    // -----------------------------------------------------------------------
    // G2: the leaf carries its attempt
    // -----------------------------------------------------------------------

    /// A host that logs every call by leaf name and would kill or remove
    /// whatever it is asked to.
    struct Obliging {
        calls: Mutex<Vec<String>>,
    }

    impl Host for Obliging {
        fn identity(&self) -> HostIdentity {
            HostIdentity {
                os: Os::Linux,
                arch: SIM_ARCH.to_owned(),
                boot_id: Some(HOST_BOOT.to_owned()),
            }
        }
        fn owner(&self, _: &OwnerRecord) -> Liveness {
            Liveness::Gone
        }
        fn probe_leaf(&self, leaf: &LeafRecord) -> LeafProbe {
            self.log("probe_leaf", &leaf.path);
            LeafProbe::Identified { populated: true }
        }
        fn terminate_leaf(&self, leaf: &LeafRecord, _: Duration) -> Result<(), String> {
            self.log("terminate_leaf", &leaf.path);
            Ok(())
        }
        fn remove_leaf(&self, leaf: &LeafRecord, _: &mut usize) -> Result<(), String> {
            self.log("remove_leaf", &leaf.path);
            Ok(())
        }
        fn probe_named_leaf(&self, path: &Path) -> LeafProbe {
            self.log("probe_named_leaf", path);
            LeafProbe::Identified { populated: false }
        }
        fn remove_named_leaf(&self, path: &Path, _: &mut usize) -> Result<(u64, u64), String> {
            self.log("remove_named_leaf", path);
            Ok((30, 4242))
        }
    }

    impl Obliging {
        fn log(&self, call: &str, path: &Path) {
            self.calls.lock().unwrap().push(format!(
                "{call} {}",
                path.file_name().unwrap().to_string_lossy()
            ));
        }
    }

    /// G2 (gc review, SAFETY, C03; live on the VPS before the fix). Leaf
    /// names carried a random token, and pinning checked only name shape,
    /// place and device/inode, so attempt A's (same-uid forged) registration
    /// of live attempt B's leaf made gc kill B's tree and remove B's leaf.
    /// The leaf's name now carries its attempt (`ouro-<attempt id>.leaf`, the
    /// §9.3 attempt association), and gc never acts on a registration that
    /// names another attempt's leaf, by identity or by name only. The
    /// control attempt's own leaf is acted on, so the scan did run.
    #[test]
    fn j4_w3_g2_a_registration_of_another_attempts_leaf_is_never_acted_on() {
        let fixture = Fixture::new();
        // B: live (its supervisor holds the lease), its own leaf.
        let b = fresh_id();
        let b_dir = fixture.root_of(&b);
        let b_lease = state::Lease::acquire(&b_dir.lock_path())
            .unwrap()
            .expect("B's lease");
        claim(
            &b_dir,
            "linux",
            SIM_ARCH,
            Some((std::process::id(), HOST_BOOT, 1)),
        );
        let b_leaf = own_leaf(&b);
        register_leaf(&b_dir, &b_leaf, true);
        // A: dead, registering B's leaf with its identity; D: dead,
        // registering it by name only; C: dead, its own leaf.
        let (a, a_dir, _) = dead_with_own_leaf(&fixture);
        register_leaf(&a_dir, &b_leaf, true);
        let (d, d_dir, _) = dead_with_own_leaf(&fixture);
        register_leaf(&d_dir, &b_leaf, false);
        let (c, _, _) = dead_with_own_leaf(&fixture);
        let host = Obliging {
            calls: Mutex::new(Vec::new()),
        };
        let report = pass(&fixture, &host, Options::DEFAULT.max_entries);
        let calls = host.calls.lock().unwrap().clone();
        let on_b: Vec<&String> = calls.iter().filter(|call| call.contains(&b)).collect();
        assert!(
            on_b.is_empty(),
            "gc acted on live attempt B's leaf through another attempt's registration: \
             {on_b:?}\nA: {:?}\nD: {:?}",
            only(&report, &a),
            only(&report, &d)
        );
        for (id, dir) in [(&a, &a_dir), (&d, &d_dir)] {
            let entry = only(&report, id);
            assert!(
                entry
                    .cgroup
                    .as_deref()
                    .is_some_and(|cgroup| cgroup.starts_with("retained")
                        && cgroup.contains("not this attempt's")),
                "{entry:?}"
            );
            assert!(actions(dir).is_empty(), "{id}: {:?}", actions(dir));
        }
        assert!(
            calls
                .iter()
                .any(|call| call.starts_with("terminate_leaf") && call.contains(&c)),
            "the control attempt's own leaf is acted on: {calls:?}"
        );
        assert_eq!(only(&report, &b).action, "retained");
        drop(b_lease);
    }

    // -----------------------------------------------------------------------
    // G3: the removal's intent is durable before `rmdir`
    // -----------------------------------------------------------------------

    /// Fails, with ENOSPC, the first gc record that adds `action` to jail
    /// state (the record written right after the `rmdir` it follows).
    struct FailRecordOf {
        action: &'static str,
        state_path: PathBuf,
        fired: Mutex<bool>,
    }

    impl state::PersistIo for FailRecordOf {
        fn write(
            &self,
            site: state::Site,
            file: &mut std::fs::File,
            bytes: &[u8],
        ) -> std::io::Result<usize> {
            let contains = |haystack: &[u8]| {
                haystack
                    .windows(self.action.len())
                    .any(|window| window == self.action.as_bytes())
            };
            let mut fired = self.fired.lock().unwrap();
            if site == state::Site::GcRecord
                && !*fired
                && contains(bytes)
                && !std::fs::read(&self.state_path).is_ok_and(|now| contains(&now))
            {
                *fired = true;
                return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
            }
            std::io::Write::write(file, bytes)
        }
    }

    /// G3 (gc review, CORRECTNESS). The removal deleted the leaf before
    /// recording anything, so a crash or a failed record right after the
    /// `rmdir` stranded the attempt: every later pass found the leaf absent,
    /// retained scratch (and vendor state, for the empty leaf) and exited 0.
    /// The intent is now durable before the `rmdir`, and a later pass
    /// finishes from it (or from `gc_terminated_orphan`): the leaf gc
    /// verified empty is gone, so the tree's end is verified.
    #[test]
    fn j4_w3_g3_a_failed_record_after_rmdir_never_strands_the_attempt() {
        let mut problems = Vec::new();
        for (label, start) in [("empty leaf", Cgroup::Empty), ("orphan", Cgroup::Populated)] {
            let fixture = Fixture::new();
            let (id, dir, leaf) = dead_with_own_leaf(&fixture);
            enforced_receipt_with_leaf(&dir, HOST_BOOT, &leaf);
            let vendor = vendor_state_pending(&dir);
            let scratch = managed_scratch(&dir, 3);
            let host = Stateful::new(&dir, start);
            let seam = Arc::new(FailRecordOf {
                action: "gc_removed_cgroup",
                state_path: dir.state_path(),
                fired: Mutex::new(false),
            });
            let first = state::with_persist_io(seam.clone(), || {
                pass(&fixture, &host, Options::DEFAULT.max_entries)
            });
            assert!(
                *seam.fired.lock().unwrap(),
                "{label}: the record was never written"
            );
            assert_eq!(host.now(), Cgroup::Gone, "{label}: the rmdir happened");
            if first.incomplete.is_empty() {
                problems.push(format!("{label}: a failed record left a complete pass"));
            }
            let intents = host.intent_before_rmdir.lock().unwrap().clone();
            if intents != [true] {
                problems.push(format!(
                    "{label}: the removal's intent was not durable before the rmdir: {intents:?}"
                ));
            }
            let mut last = None;
            for _ in 0..3 {
                last = Some(pass(&fixture, &host, Options::DEFAULT.max_entries));
            }
            let last = last.unwrap();
            let entry = only(&last, &id);
            if scratch.exists() || vendor.exists() {
                problems.push(format!(
                    "{label}: stranded after 3 more passes: scratch kept {}, vendor state kept \
                     {}, incomplete {:?}: {entry:?}",
                    scratch.exists(),
                    vendor.exists(),
                    last.incomplete
                ));
            }
            let cleanup = read_json(&dir.state_path())["state_cleanup"].clone();
            if cleanup != "complete" {
                problems.push(format!("{label}: state_cleanup {cleanup}"));
            }
            if !last.incomplete.is_empty() {
                problems.push(format!("{label}: {:?}", last.incomplete));
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    // -----------------------------------------------------------------------
    // G4: a finished attempt costs O(1) per pass and is not listed again
    // -----------------------------------------------------------------------

    /// G4 (gc review, CORRECTNESS, an S7 regression). Every non-retained
    /// attempt root was listed and charged on every pass (about six entries
    /// per finished attempt), so beyond about 16,600 finished attempts gc
    /// exited 1 forever and the attempts sorting last were never cleaned.
    /// Reproduction (bound 13): four finished attempts of another boot use
    /// 5 + 4 x 2 entries each pass, and the last attempt's scratch was never
    /// reached in 10 passes. A finished attempt now costs its one name.
    #[test]
    fn j4_w3_g4_a_finished_attempt_costs_its_name_only() {
        let fixture = Fixture::new();
        let mut ids: Vec<String> = (0..5).map(|_| fresh_id()).collect();
        ids.sort();
        for id in &ids {
            let dir = fixture.root_of(id);
            free_lock(&dir);
            claim_dead_owner(&dir, OTHER_BOOT);
        }
        let last = AttemptDir::new(
            &fixture.data,
            &AttemptId::parse(ids.last().unwrap()).unwrap(),
        );
        let scratch = managed_scratch(&last, 1);
        let host = Stateful::new(&last, Cgroup::Gone);
        let mut passes = Vec::new();
        for _ in 0..10 {
            let report = pass(&fixture, &host, 13);
            passes.push((report.budget.charged, report.incomplete.len()));
            if !scratch.exists() {
                break;
            }
        }
        assert!(
            !scratch.exists(),
            "the last attempt was never reached: (charged, incomplete) per pass {passes:?}"
        );
        assert!(passes.len() <= 2, "{passes:?}");
        // Every attempt is finished: one entry each, nothing incomplete.
        let report = pass(&fixture, &host, 13);
        assert_eq!(report.budget.charged, 5, "{:?}", report.budget);
        assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
        for id in &ids {
            assert!(
                only(&report, id).reason.starts_with("finished"),
                "{:?}",
                only(&report, id)
            );
        }
    }

    /// G4's other half: only an attempt with nothing left is finished. A leaf
    /// gc could not verify (it may be verifiable later: a gc run outside the
    /// delegated scope), an owner whose liveness is unknown, pending vendor
    /// state the records do not permit removing yet, retained managed
    /// scratch, or a temporary file gc does not remove keeps the attempt
    /// visited and reported; a dry run records nothing.
    /// The retained leaf is acted on as soon as a later pass can verify it.
    #[test]
    fn j4_w3_g4_an_attempt_with_something_left_is_never_finished() {
        use super::scripted::Scripted;
        let finished = |dir: &AttemptDir| {
            actions(dir)
                .iter()
                .any(|action| action["action"] == "gc_finished")
        };
        // A leaf gc cannot verify yet.
        let fixture = Fixture::new();
        let (id, dir, _) = dead_with_own_leaf(&fixture);
        let host = Scripted::new(Liveness::Gone, LeafProbe::Unverifiable("no scope".into()));
        pass(&fixture, &host, Options::DEFAULT.max_entries);
        assert!(!finished(&dir), "an unverifiable leaf: {:?}", actions(&dir));
        let host = Scripted::new(Liveness::Gone, LeafProbe::Identified { populated: true });
        let report = pass(&fixture, &host, Options::DEFAULT.max_entries);
        assert_eq!(
            only(&report, &id).cgroup.as_deref(),
            Some("terminated_orphan_and_removed"),
            "{:?}",
            only(&report, &id)
        );
        // An owner whose liveness is unknown.
        let fixture = Fixture::new();
        let id = fresh_id();
        let dir = fixture.root_of(&id);
        free_lock(&dir);
        claim_dead_owner(&dir, HOST_BOOT);
        let host = Scripted::new(Liveness::Unknown("no /proc".into()), LeafProbe::Absent);
        pass(&fixture, &host, Options::DEFAULT.max_entries);
        assert!(!finished(&dir), "an unknown owner: {:?}", actions(&dir));
        // Vendor state the records do not permit removing yet.
        let fixture = Fixture::new();
        let (_, dir, leaf) = dead_with_own_leaf(&fixture);
        enforced_receipt_with_leaf(&dir, HOST_BOOT, &leaf);
        let vendor = vendor_state_pending(&dir);
        let host = Scripted::new(Liveness::Gone, LeafProbe::Absent);
        pass(&fixture, &host, Options::DEFAULT.max_entries);
        assert!(vendor.exists());
        assert!(!finished(&dir), "pending vendor state: {:?}", actions(&dir));
        // Managed scratch kept because nothing verifies the tree's end (the
        // leaf is gone, and gc never saw it empty): reported every pass.
        let fixture = Fixture::new();
        let (_, dir, _) = dead_with_own_leaf(&fixture);
        let scratch = managed_scratch(&dir, 1);
        let host = Scripted::new(Liveness::Gone, LeafProbe::Absent);
        pass(&fixture, &host, Options::DEFAULT.max_entries);
        assert!(scratch.exists());
        assert!(!finished(&dir), "retained scratch: {:?}", actions(&dir));
        // A temporary file gc does not remove.
        let fixture = Fixture::new();
        let id = fresh_id();
        let dir = fixture.root_of(&id);
        free_lock(&dir);
        claim_dead_owner(&dir, OTHER_BOOT);
        private_file(&dir.root().join(".planted.tmp"), b"x");
        let host = Scripted::new(Liveness::Gone, LeafProbe::Absent);
        pass(&fixture, &host, Options::DEFAULT.max_entries);
        assert!(
            !finished(&dir),
            "a planted temporary file: {:?}",
            actions(&dir)
        );
        std::fs::remove_file(dir.root().join(".planted.tmp")).unwrap();
        // A dry run records nothing; the real pass then finishes it.
        gc::gc_with(&fixture.context(), &gc_args(true), &host, Options::DEFAULT).unwrap();
        assert!(!finished(&dir), "a dry run: {:?}", actions(&dir));
        pass(&fixture, &host, Options::DEFAULT.max_entries);
        assert!(finished(&dir), "nothing left: {:?}", actions(&dir));
    }

    // -----------------------------------------------------------------------
    // G5: a record gc repeats is kept once, with a count
    // -----------------------------------------------------------------------

    /// G5 (gc review, CORRECTNESS). While a leaf could not be emptied, every
    /// pass appended another `gc_terminating_orphan` (~300 bytes), until
    /// jail-state.json passed gc's 1 MiB read cap and the attempt read as
    /// corrupt. A repeated record is now kept once with a count and its
    /// first and last time, so jail state stops growing.
    #[test]
    fn j4_w3_g5_a_repeated_gc_record_is_kept_once_with_a_count() {
        let fixture = Fixture::new();
        let (_, dir, leaf) = dead_with_own_leaf(&fixture);
        enforced_receipt_with_leaf(&dir, HOST_BOOT, &leaf);
        let mut host = Stateful::new(&dir, Cgroup::Populated);
        host.kill_works = false;
        let passes = 30;
        let mut sizes = Vec::new();
        for _ in 0..passes {
            let report = pass(&fixture, &host, Options::DEFAULT.max_entries);
            assert!(
                !report.incomplete.is_empty(),
                "an unverified kill is incomplete"
            );
            sizes.push(std::fs::metadata(dir.state_path()).unwrap().len());
        }
        let recorded = actions(&dir);
        assert_eq!(
            recorded.len(),
            1,
            "jail-state.json grew from {} to {} bytes over {passes} passes: {} records",
            sizes[0],
            sizes[passes - 1],
            recorded.len()
        );
        assert_eq!(recorded[0]["action"], "gc_terminating_orphan");
        assert_eq!(recorded[0]["count"], passes);
        assert!(recorded[0]["at"].as_str() <= recorded[0]["last_at"].as_str());
        assert!(
            sizes[passes - 1] - sizes[1] < 16,
            "jail state keeps growing: {sizes:?}"
        );
    }

    // -----------------------------------------------------------------------
    // G6: lost integrity retains managed scratch in every boot
    // -----------------------------------------------------------------------

    /// G6 (gc review, CORRECTNESS/SPEC). Lost boundary integrity keeps the
    /// leaf and the scratch for explicit recovery in the same boot, but the
    /// other-boot rule ran first, so after a reboot the same records lost
    /// their managed scratch. Lost integrity retains it in every boot.
    #[test]
    fn j4_w3_g6_lost_integrity_retains_managed_scratch_in_every_boot() {
        let mut removed = Vec::new();
        for boot in [HOST_BOOT, OTHER_BOOT] {
            let fixture = Fixture::new();
            let id = fresh_id();
            let dir = fixture.root_of(&id);
            free_lock(&dir);
            claim_dead_owner(&dir, boot);
            let leaf = own_leaf(&id);
            register_leaf(&dir, &leaf, true);
            let mut receipt = enforced_receipt_with_leaf(&dir, boot, &leaf);
            receipt["lifetime"]["integrity"] = json!("lost");
            json_file(&dir.receipt_path(), &receipt);
            let scratch = managed_scratch(&dir, 1);
            let host = Stateful::new(&dir, Cgroup::Empty);
            let report = pass(&fixture, &host, Options::DEFAULT.max_entries);
            let entry = only(&report, &id);
            removed.push((boot, !scratch.exists(), entry.scratch.clone()));
            assert_eq!(host.now(), Cgroup::Empty, "{boot}: the leaf is kept");
        }
        assert!(
            removed.iter().all(|(_, gone, _)| !gone),
            "managed scratch removed despite lost integrity: {removed:?}"
        );
    }
}
