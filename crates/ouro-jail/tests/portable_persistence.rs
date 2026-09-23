//! J4 slice R: records under every persistence failure, control backpressure
//! and the first-cause rule for the reported error.
//!
//! - R02 (jail-v1 §7, §13.2, §13.3): disk-full, a short write then an I/O
//!   error, a failed file sync, rename or directory sync at each named site
//!   (P1 claim ... P13 gc proxy directory, `state::Site`) leaves every record
//!   file parseable, `jail.json` a valid receipt no later than the phase being
//!   written, no revision reused, no control message acknowledging a
//!   transition that was not persisted, the exit code S5 decides (125 before
//!   exec, 1 after) and a following `gc` keeping everything. A stalled sync
//!   never delays the wall, and persistence that makes no progress within
//!   §13.3's 5-second budget stops the child with the transition
//!   unacknowledged.
//! - N6: a failed `policy.json` write is a refusal with a refused receipt.
//! - R03, control half, and N4: control backpressure never delays the wall,
//!   an undelivered terminal frame is counted, and a queued frame is delivered
//!   once the reader returns.
//! - D5's remainder: the first error, not the last, is the run's reported
//!   error and drives its exit code.
//!
//! Portable: the platform is simulated, the filesystem is real, and every
//! failure is injected through `state::PersistIo`, the seam each durable
//! write goes through.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::fd::IntoRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use clap::Parser as _;
use ouro_jail::capability::{Capability, CapabilityScope, CapabilityStatus};
use ouro_jail::config::EnvSettings;
use ouro_jail::observer::CoverageSummary;
use ouro_jail::platform::{
    BoundaryIdentity, Deadline, OwnerIdentity, PlanRequest, Platform, PlatformIdentity,
    PreparedExecution, PreparedPlan, RunEvent, RunningExecution, Sinks, StopReason, Teardown,
    TreeObservation,
};
use ouro_jail::records::{JailError, NativeLifetime, Os, Receipt, rfc3339_utc};
use ouro_jail::state::{PersistIo, Site};
use ouro_jail::{cli, state, supervisor};
use serde_json::Value;

mod common;

// ---------------------------------------------------------------------------
// A simulated contained platform
// ---------------------------------------------------------------------------

/// What the simulated target does once released.
#[derive(Clone, Debug)]
enum Scenario {
    /// Exec confirmed, then exit 0.
    Plain,
    /// Exec confirmed, then the boundary reports a lost integrity, then exit 0.
    Integrity,
    /// The target exec fails with ENOENT.
    ExecError,
    /// Exactly these events, then exit 0 (a requested stop ends in SIGTERM).
    Script(Vec<RunEvent>),
    /// Exec confirmed, then real time: the wall expires at the deadline the
    /// supervisor passes, a requested stop ends the target with SIGTERM, and
    /// the target exits by itself after `exit_after`.
    Timed { exit_after: Duration },
}

/// What the supervisor asked of the simulated platform, and when.
#[derive(Default, Debug)]
struct SimLog {
    released_at: Option<Instant>,
    stops: Vec<(StopReason, Instant)>,
}

#[derive(Clone)]
struct Sim {
    scenario: Scenario,
    log: Arc<Mutex<SimLog>>,
}

impl Sim {
    fn new(scenario: Scenario) -> Sim {
        Sim {
            scenario,
            log: Arc::default(),
        }
    }
}

fn verified_tree() -> TreeObservation {
    TreeObservation {
        tree_empty: Some(true),
        verified_at: Some(SystemTime::now()),
        verification_scope: "attempt_tree".into(),
        integrity: "verified".into(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    ouro_jail::canonical::sha256_prefixed(bytes)
}

impl Platform for Sim {
    fn owner_identity(&self) -> Option<OwnerIdentity> {
        Some(OwnerIdentity {
            pid: std::process::id(),
            boot_id: "00000000-0000-4000-8000-000000000001".into(),
            start_time_ticks: 1,
        })
    }
    fn identity(&self) -> PlatformIdentity {
        PlatformIdentity {
            os: Os::Linux,
            arch: "simulation".into(),
            kernel: "simulated".into(),
        }
    }
    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        plan.requirements
            .iter()
            .map(|name| Capability {
                name: name.clone(),
                status: CapabilityStatus::Available,
                scope: CapabilityScope::Tree,
                mechanism: Some("simulation".into()),
                reason_code: Some("ok".into()),
                measured_at: Some(rfc3339_utc(SystemTime::now())),
                evidence_ref: Some("J4 persistence simulation".into()),
            })
            .collect()
    }
    fn prepare(&self, _: PreparedPlan, _: Sinks) -> Result<Box<dyn PreparedExecution>, JailError> {
        Ok(Box::new(SimPrepared(self.clone())))
    }
}

struct SimPrepared(Sim);

impl PreparedExecution for SimPrepared {
    fn boundary(&self) -> BoundaryIdentity {
        BoundaryIdentity {
            boundary: "pid_namespace".into(),
            verification_scope: "attempt_tree".into(),
            native: Some(NativeLifetime {
                os: Os::Linux,
                details: serde_json::Map::default(),
            }),
            process: Some(ouro_jail::records::ProcessRecord {
                pid: 2,
                identity: ouro_jail::records::ProcessIdentity {
                    kind: "linux_boot_start".into(),
                    value: serde_json::from_value(serde_json::json!({
                        "boot_id": "00000000-0000-4000-8000-000000000001",
                        "start_time_ticks": 1
                    }))
                    .unwrap(),
                },
            }),
            backend: Some("simulation".into()),
            backend_version: Some("1".into()),
        }
    }
    fn applied(&self) -> Option<ouro_jail::records::Applied> {
        use ouro_jail::records::{Applied, AppliedFilesystem, AppliedNetwork, AppliedSyscalls};
        Some(Applied {
            filesystem: Some(AppliedFilesystem {
                mechanism: "simulation".into(),
                protected_coverage: "none".into(),
                mounts: Vec::new(),
            }),
            network: AppliedNetwork {
                mode: "none".into(),
                mechanism: Some("simulation".into()),
                allowed_hosts: Vec::new(),
            },
            syscalls: Some(AppliedSyscalls {
                mechanism: "simulation".into(),
                digest: sha256(b"simulation"),
            }),
            limits: Vec::new(),
            environment_names: Vec::new(),
            removed_environment_names: Vec::new(),
        })
    }
    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, JailError> {
        self.0.log.lock().unwrap().released_at = Some(Instant::now());
        Ok(Box::new(SimRunning {
            sim: self.0,
            step: 0,
            stopped: false,
            wall_reported: false,
            integrity_lost: false,
        }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown {
            tree: Some(verified_tree()),
        })
    }
}

struct SimRunning {
    sim: Sim,
    step: usize,
    stopped: bool,
    wall_reported: bool,
    integrity_lost: bool,
}

impl RunningExecution for SimRunning {
    fn integrity_lost(&self) -> bool {
        self.integrity_lost
    }
    fn wait(&mut self, deadline: Deadline) -> RunEvent {
        self.step += 1;
        if self.stopped {
            return RunEvent::TargetSignaled { signal: 15 };
        }
        match &self.sim.scenario {
            Scenario::Plain => match self.step {
                1 => RunEvent::ExecConfirmed,
                _ => RunEvent::TargetExited { code: 0 },
            },
            Scenario::Integrity => match self.step {
                1 => RunEvent::ExecConfirmed,
                2 => {
                    self.integrity_lost = true;
                    RunEvent::Poll
                }
                _ => RunEvent::TargetExited { code: 0 },
            },
            Scenario::ExecError => RunEvent::ExecError {
                errno: "ENOENT".into(),
            },
            Scenario::Script(events) => events
                .get(self.step - 1)
                .cloned()
                .unwrap_or(RunEvent::TargetExited { code: 0 }),
            Scenario::Timed { exit_after } => {
                if self.step == 1 {
                    return RunEvent::ExecConfirmed;
                }
                let released = self.sim.log.lock().unwrap().released_at.unwrap();
                if !self.wall_reported && deadline.at.is_some_and(|at| Instant::now() >= at) {
                    self.wall_reported = true;
                    return RunEvent::WallExpired;
                }
                if released.elapsed() >= *exit_after {
                    return RunEvent::TargetExited { code: 0 };
                }
                std::thread::sleep(Duration::from_millis(2));
                RunEvent::Poll
            }
        }
    }
    fn request_stop(&mut self, reason: StopReason) {
        self.stopped = true;
        self.sim
            .log
            .lock()
            .unwrap()
            .stops
            .push((reason, Instant::now()));
    }
    fn wait_tree(&mut self, _: Duration) -> TreeObservation {
        if self.integrity_lost {
            return TreeObservation {
                tree_empty: None,
                verified_at: None,
                verification_scope: "attempt_tree".into(),
                integrity: "lost".into(),
            };
        }
        verified_tree()
    }
    fn observer_summary(&mut self) -> Option<CoverageSummary> {
        None
    }
}

// ---------------------------------------------------------------------------
// Fault injection through the persistence seam
// ---------------------------------------------------------------------------

/// One way a step of a durable replacement fails.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    /// The disk is full: the first write fails with ENOSPC.
    Enospc,
    /// The first write stores half the bytes; the next one fails with EIO.
    ShortWriteThenEio,
    /// The file sync fails with EIO.
    FsyncError,
    /// The rename (or the claim's exclusive link) fails with EIO.
    RenameError,
    /// The directory sync after the rename fails with EIO.
    DirSyncError,
}

impl Fault {
    const ALL: [Fault; 5] = [
        Fault::Enospc,
        Fault::ShortWriteThenEio,
        Fault::FsyncError,
        Fault::RenameError,
        Fault::DirSyncError,
    ];

    fn name(self) -> &'static str {
        match self {
            Fault::Enospc => "enospc",
            Fault::ShortWriteThenEio => "short_write_then_eio",
            Fault::FsyncError => "fsync_error",
            Fault::RenameError => "rename_error",
            Fault::DirSyncError => "dir_sync_error",
        }
    }
}

fn eio() -> std::io::Error {
    std::io::Error::from_raw_os_error(libc::EIO)
}

/// The record a replacement targets: `.jail.json.<uuid>.tmp` is `jail.json`.
fn target_of(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    match name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
    {
        Some(middle) => middle
            .rsplit_once('.')
            .map_or(middle.to_owned(), |(target, _uuid)| target.to_owned()),
        None => name,
    }
}

/// What every observation of the records has shown so far.
#[derive(Default)]
struct Seen {
    /// Every rule broken, with where.
    violations: Vec<String>,
    /// `revision -> bytes` of every receipt either copy showed.
    by_revision: BTreeMap<u64, Vec<u8>>,
    /// The digests (as control messages compute them) of receipts that were
    /// fully durable: renamed into place and the directory synced.
    durable: Vec<(String, String)>,
    /// Whether the fault fired, and what `jail.json` held at that moment.
    fired: bool,
    phase_at_fault: Option<String>,
}

/// A stalled step waits on this until the test releases it.
type Release = Arc<(Mutex<bool>, std::sync::Condvar)>;

/// The step a stall holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StallAt {
    FileSync,
    Rename,
}

/// What a stalled step does once the test releases it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AfterStall {
    /// It fails with EIO.
    Fail,
    /// It is performed for real and succeeds: what a slow disk does, and the
    /// one outcome that shows whether abandoned work lands later (J4 W3, P1).
    Complete,
}

/// The first `at` step at `site` blocks until the test releases it.
struct Stall {
    site: Site,
    at: StallAt,
    release: Release,
    then: AfterStall,
}

/// A [`PersistIo`] that performs every step for real, fails one step of one
/// replacement at one site, stalls one step when asked to, and checks the
/// records on disk before every step.
struct Faults {
    /// `(site, fault, target name)`: the target filter limits the fault to
    /// replacements of that record (`None`: every replacement at the site,
    /// whatever its target).
    fault: Option<(Site, Fault, Option<String>)>,
    /// Which of the replacements the filter admits fails: 0 is the first.
    nth: usize,
    stall: Option<Stall>,
    watch: Watch,
    state: Mutex<FaultState>,
}

#[derive(Default)]
struct FaultState {
    /// The target of the replacement in progress, and its site.
    current: Option<(Site, String)>,
    /// The ordinal of the replacement in progress among those the fault's
    /// site and target filter admit, when it is one of them.
    current_nth: Option<usize>,
    /// How many replacements the fault's filter has admitted so far.
    admitted: usize,
    /// A short write happened; the next write of this replacement fails.
    short_pending: bool,
    /// The last rename/link published this target; its directory sync makes
    /// it durable.
    renamed: Option<String>,
    stalled_once: bool,
    seen: Seen,
}

/// The files a check looks at.
#[derive(Clone)]
struct Watch {
    data: PathBuf,
    extra: Option<PathBuf>,
}

impl Watch {
    fn attempt_dirs(&self) -> Vec<PathBuf> {
        let Ok(listing) = std::fs::read_dir(self.data.join("attempts")) else {
            return Vec::new();
        };
        let mut dirs: Vec<PathBuf> = listing.flatten().map(|entry| entry.path()).collect();
        dirs.sort();
        dirs
    }

    /// Checks every present record and returns `jail.json`'s phase.
    fn check(&self, label: &str, seen: &mut Seen) -> Option<String> {
        let mut phase = None;
        for dir in self.attempt_dirs() {
            for name in ["jail-state.json", "policy.json"] {
                if let Ok(bytes) = std::fs::read(dir.join(name))
                    && let Err(error) = serde_json::from_slice::<Value>(&bytes)
                {
                    seen.violations
                        .push(format!("{label}: {name} does not parse: {error}"));
                }
            }
            let mut receipts = vec![dir.join("jail.json")];
            receipts.extend(self.extra.clone());
            for path in receipts {
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                let value: Value = match serde_json::from_slice(&bytes) {
                    Ok(value) => value,
                    Err(error) => {
                        seen.violations
                            .push(format!("{label}: {name} does not parse: {error}"));
                        continue;
                    }
                };
                if let Err(error) = common::check_receipt(&value) {
                    seen.violations
                        .push(format!("{label}: {name} is not a valid receipt: {error}"));
                }
                let revision = value["revision"].as_u64().unwrap_or(0);
                match seen.by_revision.get(&revision) {
                    Some(earlier) if *earlier != bytes => seen.violations.push(format!(
                        "{label}: revision {revision} reused for a different receipt in {name}"
                    )),
                    Some(_) => {}
                    None => {
                        seen.by_revision.insert(revision, bytes.clone());
                    }
                }
                if name == "jail.json" {
                    phase = value["phase"].as_str().map(str::to_owned);
                }
            }
        }
        phase
    }
}

impl Faults {
    fn new(watch: Watch) -> Faults {
        Faults {
            fault: None,
            nth: 0,
            stall: None,
            watch,
            state: Mutex::default(),
        }
    }

    fn failing(mut self, site: Site, fault: Fault, target: Option<&str>) -> Faults {
        self.fault = Some((site, fault, target.map(str::to_owned)));
        self
    }

    /// Fails the `nth` replacement the fault's filter admits instead of the
    /// first.
    fn at_nth(mut self, nth: usize) -> Faults {
        self.nth = nth;
        self
    }

    /// Blocks until released, then does what `stall.then` says.
    fn hold(&self, site: Site, at: StallAt) -> Option<AfterStall> {
        let stall = self.stall.as_ref()?;
        if stall.site != site
            || stall.at != at
            || std::mem::replace(&mut self.state.lock().unwrap().stalled_once, true)
        {
            return None;
        }
        let (lock, wake) = &*stall.release;
        let mut released = lock.lock().unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        while !*released && Instant::now() < until {
            released = wake
                .wait_timeout(released, Duration::from_millis(50))
                .unwrap()
                .0;
        }
        Some(stall.then)
    }

    /// Checks the records, then decides whether this step of `site` fails.
    fn step(&self, site: Site, step: &str, fault_here: impl Fn(Fault) -> bool) -> bool {
        let mut state = self.state.lock().unwrap();
        let state = &mut *state;
        let label = format!("before {step} at {}", site.as_str());
        let phase = self.watch.check(&label, &mut state.seen);
        let Some((fault_site, fault, target)) = &self.fault else {
            return false;
        };
        if state.seen.fired || *fault_site != site || !fault_here(*fault) {
            return false;
        }
        if let Some(target) = target
            && state.current.as_ref().map(|(_, name)| name) != Some(target)
        {
            return false;
        }
        if state.current_nth != Some(self.nth) {
            return false;
        }
        state.seen.fired = true;
        state.seen.phase_at_fault = phase;
        true
    }

    fn seen<R>(&self, read: impl FnOnce(&Seen) -> R) -> R {
        read(&self.state.lock().unwrap().seen)
    }

    fn finish(&self, label: &str) {
        let mut state = self.state.lock().unwrap();
        self.watch.check(label, &mut state.seen);
    }
}

impl PersistIo for Faults {
    fn create_new(&self, site: Site, path: &Path) -> std::io::Result<std::fs::File> {
        {
            let mut state = self.state.lock().unwrap();
            let target = target_of(path);
            state.current_nth = None;
            if let Some((fault_site, _, filter)) = &self.fault
                && *fault_site == site
                && filter.as_ref().is_none_or(|filter| *filter == target)
            {
                state.current_nth = Some(state.admitted);
                state.admitted += 1;
            }
            state.current = Some((site, target));
            state.short_pending = false;
        }
        self.step(site, "create", |_| false);
        state::RealIo.create_new(site, path)
    }

    fn write(&self, site: Site, file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<usize> {
        let short_pending = std::mem::take(&mut self.state.lock().unwrap().short_pending);
        if short_pending {
            return Err(eio());
        }
        if self.step(site, "write", |fault| {
            matches!(fault, Fault::Enospc | Fault::ShortWriteThenEio)
        }) {
            match self.fault.as_ref().map(|(_, fault, _)| *fault) {
                Some(Fault::Enospc) => return Err(std::io::Error::from_raw_os_error(libc::ENOSPC)),
                _ => {
                    self.state.lock().unwrap().short_pending = true;
                    let half = (bytes.len() / 2).max(1);
                    return state::RealIo.write(site, file, &bytes[..half]);
                }
            }
        }
        state::RealIo.write(site, file, bytes)
    }

    fn sync_file(&self, site: Site, file: &std::fs::File) -> std::io::Result<()> {
        if self.hold(site, StallAt::FileSync) == Some(AfterStall::Fail) {
            return Err(eio());
        }
        if self.step(site, "file sync", |fault| fault == Fault::FsyncError) {
            return Err(eio());
        }
        state::RealIo.sync_file(site, file)
    }

    fn rename(&self, site: Site, from: &Path, to: &Path) -> std::io::Result<()> {
        if self.hold(site, StallAt::Rename) == Some(AfterStall::Fail) {
            return Err(eio());
        }
        if self.step(site, "rename", |fault| fault == Fault::RenameError) {
            return Err(eio());
        }
        state::RealIo.rename(site, from, to)?;
        self.state.lock().unwrap().renamed = Some(target_of(to));
        Ok(())
    }

    fn link(&self, site: Site, from: &Path, to: &Path) -> std::io::Result<()> {
        if self.step(site, "link", |fault| fault == Fault::RenameError) {
            return Err(eio());
        }
        state::RealIo.link(site, from, to)?;
        self.state.lock().unwrap().renamed = Some(target_of(to));
        Ok(())
    }

    fn sync_dir(&self, site: Site, dir: &Path) -> std::io::Result<()> {
        if self.step(site, "directory sync", |fault| fault == Fault::DirSyncError) {
            return Err(eio());
        }
        state::RealIo.sync_dir(site, dir)?;
        let mut state = self.state.lock().unwrap();
        if state.renamed.take().as_deref() == Some("jail.json")
            && let Ok(bytes) = std::fs::read(dir.join("jail.json"))
            && let Ok(receipt) = serde_json::from_slice::<Receipt>(&bytes)
        {
            let digest = sha256(&serde_json::to_vec(&receipt).unwrap());
            let phase = serde_json::to_value(receipt.phase).unwrap();
            state
                .seen
                .durable
                .push((digest, phase.as_str().unwrap().to_owned()));
        }
        Ok(())
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
    extra: PathBuf,
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// What one run produced.
struct Outcome {
    report: supervisor::RunReport,
    /// Every control frame the reader got, parsed, in order.
    frames: Vec<Value>,
    /// When each frame reached the reader.
    arrivals: Vec<Instant>,
    /// When the run returned.
    finished_at: Instant,
    /// Bytes after the last LF: a frame that was cut short.
    torn_tail: Vec<u8>,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = common::private_tempdir();
        let root = dir.path().canonicalize().unwrap();
        let fixture = Fixture {
            config: root.join("config"),
            data: root.join("data"),
            workspace: root.join("workspace"),
            extra: root.join("receipts").join("receipt.json"),
            root,
            _root: dir,
        };
        for path in [
            &fixture.config,
            &fixture.data,
            &fixture.workspace,
            &fixture.root.join("receipts"),
        ] {
            private_dir(path);
        }
        private_dir(&fixture.config.join("launch"));
        let launch = fixture.config.join("launch").join("plain.toml");
        std::fs::write(
            &launch,
            "name = \"plain\"\njail = \"tool\"\nstate_subdirs = [\"a/b\"]\n",
        )
        .unwrap();
        std::fs::set_permissions(&launch, std::fs::Permissions::from_mode(0o600)).unwrap();
        fixture
    }

    fn watch(&self) -> Watch {
        Watch {
            data: self.data.clone(),
            extra: Some(self.extra.clone()),
        }
    }

    fn context(&self, sim: Sim) -> supervisor::Context {
        self.context_on(Box::new(sim))
    }

    fn context_on(&self, platform: Box<dyn Platform>) -> supervisor::Context {
        supervisor::Context {
            platform,
            env_settings: EnvSettings {
                config_dir: Some(self.config.clone()),
                data_dir: Some(self.data.clone()),
                ..Default::default()
            },
            cwd: self.workspace.clone(),
            home: Some(self.root.join("home")),
            env_lookup: Box::new(|_| None),
        }
    }

    fn args(&self, flags: &[String]) -> cli::RunArgs {
        let mut argv: Vec<String> = vec!["ouro-jail".into(), "run".into()];
        argv.push("--workspace".into());
        argv.push(self.workspace.display().to_string());
        argv.extend(flags.iter().cloned());
        argv.push("--".into());
        argv.push("simulated-target".into());
        let cli::Command::Run(args) = cli::Cli::parse_from(argv).command else {
            unreachable!()
        };
        *args
    }

    /// Runs with a control pipe that a reader drains from the start
    /// (`reader_delay: None`) or after a delay, over `io`.
    fn run_with(
        &self,
        sim: Sim,
        flags: &[&str],
        io: Arc<dyn PersistIo + Send + Sync>,
        control: Control,
    ) -> Outcome {
        self.run_full(Box::new(sim), flags, io, control)
    }

    /// Runs on `platform` with a control pipe drained from the start.
    fn run_on(
        &self,
        platform: Box<dyn Platform>,
        flags: &[&str],
        io: Arc<dyn PersistIo + Send + Sync>,
    ) -> Outcome {
        self.run_full(platform, flags, io, Control::Drained)
    }

    fn run_full(
        &self,
        platform: Box<dyn Platform>,
        flags: &[&str],
        io: Arc<dyn PersistIo + Send + Sync>,
        control: Control,
    ) -> Outcome {
        let (reader, writer) = std::io::pipe().unwrap();
        if control == Control::FullNeverRead || matches!(control, Control::FullReadAfter(_)) {
            fill(&writer);
        }
        let fd = writer.into_raw_fd();
        let mut flags: Vec<String> = flags.iter().map(|flag| (*flag).to_owned()).collect();
        flags.push("--control-fd".into());
        flags.push(fd.to_string());
        let args = self.args(&flags);
        let drain = match control {
            Control::Drained => Some(Duration::ZERO),
            Control::FullReadAfter(delay) => Some(delay),
            Control::FullNeverRead => None,
        };
        // The reader stops at EOF, or once the run has returned and the pipe
        // is empty: a run that refused before it adopted the descriptor never
        // closes it, and everything the run will ever write is in the pipe by
        // the time it returns (its final drain is inside the run).
        // A reader that never reads is still there: the pipe stays full and
        // open (backpressure), rather than closed (a broken pipe).
        let (reader, kept_reader) = if drain.is_some() {
            (Some(reader), None)
        } else {
            (None, Some(reader))
        };
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let collector = drain.zip(reader).map(|(delay, mut reader)| {
            use std::os::fd::AsRawFd as _;
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                ouro_jail::trace::set_nonblocking(reader.as_raw_fd()).unwrap();
                let mut pending = Vec::new();
                let mut lines: Vec<(Vec<u8>, Instant)> = Vec::new();
                let mut chunk = [0u8; 65536];
                loop {
                    match reader.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(count) => {
                            pending.extend_from_slice(&chunk[..count]);
                            while let Some(at) = pending.iter().position(|byte| *byte == b'\n') {
                                let line: Vec<u8> = pending.drain(..=at).collect();
                                if line.len() > 1 {
                                    lines.push((line[..line.len() - 1].to_vec(), Instant::now()));
                                }
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if done.load(std::sync::atomic::Ordering::SeqCst) {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("reading the control pipe: {error}"),
                    }
                }
                (lines, pending)
            })
        });
        let ctx = self.context_on(platform);
        let report = state::with_persist_io(io, || supervisor::run(&ctx, &args));
        let finished_at = Instant::now();
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        let (lines, torn_tail) = match collector {
            Some(handle) => handle.join().unwrap(),
            None => (Vec::new(), Vec::new()),
        };
        drop(kept_reader);
        let mut frames = Vec::new();
        let mut arrivals = Vec::new();
        for (line, at) in lines {
            frames.push(serde_json::from_slice(&line).unwrap_or_else(|error| {
                panic!(
                    "a control frame does not parse ({error}): {}",
                    String::from_utf8_lossy(&line)
                )
            }));
            arrivals.push(at);
        }
        Outcome {
            report,
            frames,
            arrivals,
            finished_at,
            torn_tail,
        }
    }

    fn run(&self, sim: Sim, flags: &[&str], io: Arc<dyn PersistIo + Send + Sync>) -> Outcome {
        self.run_with(sim, flags, io, Control::Drained)
    }

    fn gc(&self, io: Arc<dyn PersistIo + Send + Sync>) -> supervisor::GcReport {
        let ctx = self.context(Sim::new(Scenario::Plain));
        let report = state::with_persist_io(io, || {
            supervisor::gc(
                &ctx,
                &cli::GcArgs {
                    dry_run: false,
                    json: false,
                },
            )
        });
        match report {
            Ok(report) => report,
            Err(error) => panic!("gc must scan: {error}"),
        }
    }

    fn attempt(&self) -> PathBuf {
        let dirs = self.watch().attempt_dirs();
        assert_eq!(dirs.len(), 1, "one attempt: {dirs:?}");
        dirs[0].clone()
    }
}

/// How the control pipe's reader behaves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Control {
    /// A reader drains it from the start.
    Drained,
    /// The pipe is full before the run and nobody reads it.
    FullNeverRead,
    /// The pipe is full before the run and a reader starts after the delay.
    FullReadAfter(Duration),
}

/// Fills a pipe until a nonblocking write would block, with newlines (which
/// the frame reader skips).
fn fill(writer: &std::io::PipeWriter) {
    use std::os::fd::AsRawFd as _;
    ouro_jail::trace::set_nonblocking(writer.as_raw_fd()).unwrap();
    let mut writer = writer;
    let chunk = [b'\n'; 4096];
    loop {
        match writer.write(&chunk) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("filling the control pipe: {error}"),
        }
    }
    loop {
        match writer.write(b"\n") {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("filling the control pipe: {error}"),
        }
    }
}

fn real() -> Arc<dyn PersistIo + Send + Sync> {
    Arc::new(state::RealIo)
}

// ---------------------------------------------------------------------------
// R02: every site crossed with every fault
// ---------------------------------------------------------------------------

/// How a site is reached, and what its failure must produce.
struct SiteCase {
    site: Site,
    /// The scenario and flags that reach the site.
    scenario: Scenario,
    launch: bool,
    /// The latest phase `jail.json` may show when the fault fires (0: none,
    /// 1: prepared, 2: enforced, 3: settled or refused).
    max_rank: u8,
    /// S5: 125 before exec, 1 after.
    exit_code: i32,
}

fn rank(phase: Option<&str>) -> u8 {
    match phase {
        None => 0,
        Some("prepared") => 1,
        Some("enforced") => 2,
        Some(_) => 3,
    }
}

fn run_site_cases() -> Vec<SiteCase> {
    let case = |site, scenario, launch, max_rank, exit_code| SiteCase {
        site,
        scenario,
        launch,
        max_rank,
        exit_code,
    };
    vec![
        case(Site::Claim, Scenario::Plain, false, 0, 125),
        case(Site::Policy, Scenario::Plain, false, 0, 125),
        case(Site::LaunchState, Scenario::Plain, true, 0, 125),
        case(Site::Boundary, Scenario::Plain, false, 0, 125),
        case(Site::PreparedReceipt, Scenario::Plain, false, 1, 125),
        case(Site::EnforcedReceipt, Scenario::Plain, false, 2, 1),
        case(Site::IntegrityReceipt, Scenario::Integrity, false, 2, 1),
        case(Site::PendingReceipt, Scenario::Plain, true, 3, 1),
        case(Site::TerminalReceipt, Scenario::Plain, false, 3, 1),
        case(Site::RefusedReceipt, Scenario::ExecError, false, 3, 125),
        case(Site::CleanupRecord, Scenario::Plain, true, 3, 1),
    ]
}

/// Every control frame acknowledges a receipt that was fully durable, and
/// frames are numbered in order.
fn acknowledged_only_what_persisted(
    label: &str,
    outcome: &Outcome,
    faults: &Faults,
) -> Vec<String> {
    let mut problems = Vec::new();
    let durable = faults.seen(|seen| seen.durable.clone());
    let mut last_seq = 0;
    for frame in &outcome.frames {
        let digest = frame["receipt_digest"].as_str().unwrap_or_default();
        if !durable.iter().any(|(known, _)| known == digest) {
            problems.push(format!(
                "{label}: control message {} ({}) acknowledges receipt {digest}, which was never \
                 durable; durable: {durable:?}",
                frame["kind"], frame["receipt_phase"]
            ));
        }
        let seq = frame["seq"].as_u64().unwrap_or(0);
        if seq <= last_seq {
            problems.push(format!("{label}: control seq {seq} after {last_seq}"));
        }
        last_seq = seq;
    }
    problems
}

/// A following `gc` keeps every record, and they still parse.
fn gc_keeps_everything(label: &str, fixture: &Fixture, faults: &Faults) -> Vec<String> {
    let mut problems = Vec::new();
    let names = [
        "jail-state.json",
        "policy.json",
        "jail.json",
        "trace.ndjson",
    ];
    let before: Vec<(PathBuf, bool)> = fixture
        .watch()
        .attempt_dirs()
        .into_iter()
        .flat_map(|dir| names.map(|name| dir.join(name)))
        .map(|path| {
            let present = path.exists();
            (path, present)
        })
        .collect();
    let gc = fixture.gc(real());
    for (path, present) in before {
        if present && !path.exists() {
            problems.push(format!("{label}: gc removed {}", path.display()));
        }
    }
    let _ = gc;
    faults.finish(&format!("{label} after gc"));
    problems
}

/// One site crossed with one fault, through a whole supervisor run.
fn run_case(case: &SiteCase, fault: Fault) -> Vec<String> {
    let label = format!("j4_r02_{}_{}", case.site.as_str(), fault.name());
    let fixture = Fixture::new();
    let faults = Arc::new(Faults::new(fixture.watch()).failing(case.site, fault, None));
    let extra = fixture.extra.display().to_string();
    let mut flags = vec!["--profile", "tool", "--receipt", extra.as_str()];
    if case.launch {
        flags.extend(["--launch", "plain"]);
    }
    let outcome = fixture.run(Sim::new(case.scenario.clone()), &flags, faults.clone());
    faults.finish(&format!("{label} at the end"));
    let mut problems = Vec::new();
    let (fired, phase_at_fault, violations) = faults.seen(|seen| {
        (
            seen.fired,
            seen.phase_at_fault.clone(),
            seen.violations.clone(),
        )
    });
    if !fired {
        problems.push(format!(
            "{label}: the fault was never injected: the site performs no such step"
        ));
    }
    problems.extend(violations);
    if rank(phase_at_fault.as_deref()) > case.max_rank {
        problems.push(format!(
            "{label}: jail.json was already {phase_at_fault:?} when this site's write failed"
        ));
    }
    if outcome.report.exit_code != case.exit_code {
        problems.push(format!(
            "{label}: exit code {} (error {:?}), S5 wants {}",
            outcome.report.exit_code,
            outcome.report.error.as_ref().map(|error| error.to_string()),
            case.exit_code
        ));
    }
    problems.extend(acknowledged_only_what_persisted(&label, &outcome, &faults));
    for dir in fixture.watch().attempt_dirs() {
        let attempt = state::AttemptDir::new(
            &fixture.data,
            &state::AttemptId::parse(&dir.file_name().unwrap().to_string_lossy()).unwrap(),
        );
        let leftover = state::leftover_temp_files(&attempt).unwrap();
        if !leftover.is_empty() {
            problems.push(format!(
                "{label}: a failed write that was not a crash left temporary files: {leftover:?}"
            ));
        }
    }
    problems.extend(gc_keeps_everything(&label, &fixture, &faults));
    problems
}

/// P12, P13 and P14: `gc`'s own writes, after a run that left work for it.
fn gc_case(site: Site, fault: Fault) -> Vec<String> {
    let label = format!("j4_r02_{}_{}", site.as_str(), fault.name());
    let fixture = Fixture::new();
    let mut flags = vec!["--profile", "tool"];
    if site == Site::GcResume {
        flags.extend(["--launch", "plain"]);
    }
    let run = fixture.run(Sim::new(Scenario::Plain), &flags, real());
    assert_eq!(run.report.exit_code, 0, "{label}: {:?}", run.report.error);
    let dir = fixture.attempt();
    // Rewind the records to what an interruption leaves for gc to finish: a
    // cleanup recorded pending (P12), a registered proxy directory the
    // supervisor never removed (P13), or (J4 wave 2) the temporary file a
    // crash left, of an owner recorded in another boot, which gc removes and
    // records in `gc_actions` (P14).
    let mut state: Value =
        serde_json::from_slice(&std::fs::read(dir.join("jail-state.json")).unwrap()).unwrap();
    if site == Site::GcRecord {
        // Both records name the other boot, or they would disagree.
        let other_boot = "00000000-0000-4000-8000-00000000b0b0";
        state["owner"]["boot_id"] = other_boot.into();
        let mut receipt: Value =
            serde_json::from_slice(&std::fs::read(dir.join("jail.json")).unwrap()).unwrap();
        receipt["process"]["identity"]["value"]["boot_id"] = other_boot.into();
        std::fs::write(
            dir.join("jail.json"),
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
        let temp = dir.join(format!(
            ".jail.json.{}.tmp",
            state::AttemptId::generate()
                .as_str()
                .trim_start_matches("att_")
        ));
        std::fs::write(&temp, b"{").unwrap();
    } else if site == Site::GcResume {
        let mut receipt: Value =
            serde_json::from_slice(&std::fs::read(dir.join("jail.json")).unwrap()).unwrap();
        receipt["state_cleanup"] = "pending".into();
        std::fs::write(
            dir.join("jail.json"),
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
        state["state_cleanup"] = "pending".into();
    } else {
        state["proxy_dir"] = serde_json::json!({
            "name": "proxy", "registered_at": "2026-09-23T00:00:00Z",
            "dev": null, "ino": null, "removed": false,
        });
    }
    std::fs::write(
        dir.join("jail-state.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();

    let faults = Arc::new(Faults::new(fixture.watch()).failing(site, fault, None));
    let failed = fixture.gc(faults.clone());
    faults.finish(&format!("{label} after the failed gc"));
    let mut problems = Vec::new();
    if !faults.seen(|seen| seen.fired) {
        problems.push(format!("{label}: the fault was never injected"));
    }
    if failed.incomplete.is_empty() {
        problems.push(format!(
            "{label}: gc reported a complete pass although its write failed (§6.4: exit 1)"
        ));
    }
    // The next pass finishes, and nothing reused a revision in between.
    let again = fixture.gc(faults.clone());
    faults.finish(&format!("{label} after the second gc"));
    if !again.incomplete.is_empty() {
        problems.push(format!(
            "{label}: the next gc pass did not finish: {:?}",
            again.incomplete
        ));
    }
    problems.extend(faults.seen(|seen| seen.violations.clone()));
    for name in [
        "jail-state.json",
        "policy.json",
        "jail.json",
        "trace.ndjson",
    ] {
        if !dir.join(name).exists() {
            problems.push(format!("{label}: gc removed {name}"));
        }
    }
    problems
}

#[test]
fn j4_r02_every_site_under_every_fault_leaves_valid_records() {
    let mut problems = Vec::new();
    for case in run_site_cases() {
        for fault in Fault::ALL {
            problems.extend(run_case(&case, fault));
        }
    }
    for site in [Site::GcResume, Site::GcProxyDir, Site::GcRecord] {
        for fault in Fault::ALL {
            problems.extend(gc_case(site, fault));
        }
    }
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// The `--receipt` copy fails at every receipt site, after the canonical copy
/// landed: no revision is reused and no transition is acknowledged.
#[test]
fn j4_r02_a_failed_receipt_copy_never_reuses_a_revision() {
    let mut problems = Vec::new();
    for case in run_site_cases()
        .into_iter()
        .filter(|case| case.site.as_str().ends_with("_receipt"))
    {
        for fault in [Fault::RenameError, Fault::DirSyncError, Fault::FsyncError] {
            let label = format!("{} copy {}", case.site.as_str(), fault.name());
            let fixture = Fixture::new();
            let faults = Arc::new(Faults::new(fixture.watch()).failing(
                case.site,
                fault,
                Some("receipt.json"),
            ));
            let extra = fixture.extra.display().to_string();
            let mut flags = vec!["--profile", "tool", "--receipt", extra.as_str()];
            if case.launch {
                flags.extend(["--launch", "plain"]);
            }
            let outcome = fixture.run(Sim::new(case.scenario.clone()), &flags, faults.clone());
            faults.finish(&format!("{label} at the end"));
            let (fired, violations) = faults.seen(|seen| (seen.fired, seen.violations.clone()));
            if !fired {
                problems.push(format!("{label}: the copy never failed"));
            }
            problems.extend(violations);
            problems.extend(acknowledged_only_what_persisted(&label, &outcome, &faults));
            if outcome.report.exit_code != case.exit_code {
                problems.push(format!(
                    "{label}: exit code {}, S5 wants {}",
                    outcome.report.exit_code, case.exit_code
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

// ---------------------------------------------------------------------------
// N6: a failed policy.json write is a refusal with a receipt
// ---------------------------------------------------------------------------

#[test]
fn j4_n6_a_failed_policy_write_refuses_with_a_refused_receipt() {
    let fixture = Fixture::new();
    let faults = Arc::new(Faults::new(fixture.watch()).failing(Site::Policy, Fault::Enospc, None));
    let outcome = fixture.run(Sim::new(Scenario::Plain), &["--profile", "tool"], faults);
    assert_eq!(
        outcome.report.exit_code, 125,
        "S5: a persistence failure before exec is a refusal: {:?}",
        outcome.report.error
    );
    let receipt = serde_json::to_value(
        outcome
            .report
            .receipt
            .as_ref()
            .expect("the refusal wrote a refused receipt"),
    )
    .unwrap();
    common::check_receipt(&receipt).unwrap();
    assert_eq!(receipt["phase"], "refused", "{receipt:#}");
    assert_eq!(receipt["outcome"]["kind"], "refused");
    assert_eq!(receipt["outcome"]["error"]["code"], "state_write_failed");
    let on_disk: Value =
        serde_json::from_slice(&std::fs::read(fixture.attempt().join("jail.json")).unwrap())
            .unwrap();
    assert_eq!(on_disk, receipt, "the receipt on disk is the one reported");
    let kinds: Vec<&Value> = outcome.frames.iter().map(|frame| &frame["kind"]).collect();
    assert_eq!(
        kinds,
        ["refused"],
        "the owner is told: {:?}",
        outcome.frames
    );
    assert!(
        !fixture.attempt().join("policy.json").exists(),
        "no partial policy.json"
    );
}

// ---------------------------------------------------------------------------
// §13.3: the persistence worker and its 5-second progress budget
// ---------------------------------------------------------------------------

/// A seam whose first file sync at `site` blocks until released and then
/// completes, as a slow disk does.
fn stalled(fixture: &Fixture, site: Site) -> (Arc<Faults>, Release) {
    stalled_at(fixture, site, StallAt::FileSync, AfterStall::Complete)
}

/// A seam whose first `at` step at `site` blocks until released, then does
/// `then`.
fn stalled_at(
    fixture: &Fixture,
    site: Site,
    at: StallAt,
    then: AfterStall,
) -> (Arc<Faults>, Release) {
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let mut faults = Faults::new(fixture.watch());
    faults.stall = Some(Stall {
        site,
        at,
        release: Arc::clone(&release),
        then,
    });
    (Arc::new(faults), release)
}

fn release(stall: &Release) {
    *stall.0.lock().unwrap() = true;
    stall.1.notify_all();
}

#[test]
fn j4_r02_a_stalled_sync_never_delays_the_wall() {
    let fixture = Fixture::new();
    let (faults, stall) = stalled_at(
        &fixture,
        Site::EnforcedReceipt,
        StallAt::FileSync,
        AfterStall::Fail,
    );
    let sim = Sim::new(Scenario::Timed {
        exit_after: Duration::from_secs(20),
    });
    let log = Arc::clone(&sim.log);
    let started = Instant::now();
    let outcome = fixture.run(sim, &["--profile", "tool", "--limit", "wall=1s"], faults);
    let elapsed = started.elapsed();
    release(&stall);
    let log = log.lock().unwrap();
    let released = log.released_at.expect("released");
    let (reason, at) = *log.stops.first().expect("the wall stopped the target");
    let late = at.duration_since(released);
    assert_eq!(reason, StopReason::WallExpiry, "{:?}", log.stops);
    assert!(
        late < Duration::from_millis(1500),
        "the 1 s wall fired {late:?} after release while the enforced receipt's sync was stalled"
    );
    assert!(
        elapsed < Duration::from_secs(12),
        "the run waited {elapsed:?} for a sync that never finished"
    );
    let kinds: Vec<&Value> = outcome.frames.iter().map(|frame| &frame["kind"]).collect();
    assert!(
        !kinds.iter().any(|kind| *kind == "exec_confirmed"),
        "exec_confirmed acknowledged a receipt that never persisted: {kinds:?}"
    );
}

#[test]
fn j4_r02_persistence_that_cannot_finish_in_5s_stops_the_child_unacknowledged() {
    let fixture = Fixture::new();
    let (faults, stall) = stalled(&fixture, Site::EnforcedReceipt);
    let sim = Sim::new(Scenario::Timed {
        exit_after: Duration::from_secs(25),
    });
    let log = Arc::clone(&sim.log);
    let started = Instant::now();
    let outcome = fixture.run(sim, &["--profile", "tool", "--limit", "wall=1h"], faults);
    let elapsed = started.elapsed();
    let on_disk: Value =
        serde_json::from_slice(&std::fs::read(fixture.attempt().join("jail.json")).unwrap())
            .unwrap();
    release(&stall);
    let log = log.lock().unwrap();
    let released = log.released_at.expect("released");
    let (reason, at) = *log
        .stops
        .first()
        .expect("persistence that cannot finish stops the child");
    let after = at.duration_since(released);
    assert_eq!(reason, StopReason::EvidenceLoss, "{:?}", log.stops);
    assert!(
        after >= Duration::from_millis(4500) && after < Duration::from_millis(7000),
        "§13.3: the stop comes when the 5 s progress budget runs out, not {after:?} after release"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "the run waited {elapsed:?}"
    );
    let kinds: Vec<&Value> = outcome.frames.iter().map(|frame| &frame["kind"]).collect();
    assert_eq!(
        kinds,
        ["prepared"],
        "the transition stays unacknowledged: {:?}",
        outcome.frames
    );
    assert_eq!(
        on_disk["phase"], "prepared",
        "the receipt stays at its last persisted phase"
    );
    common::check_receipt(&on_disk).unwrap();
    assert_eq!(outcome.report.exit_code, 1, "S5: after exec a tool error");
    let error = outcome.report.error.as_ref().expect("an error");
    assert_eq!(error.code.as_str(), "state_write_failed", "{error}");
    assert!(
        error
            .message
            .ends_with("the transition is not acknowledged"),
        "the reported error is the first cause, the stalled enforced receipt, not the terminal \
         receipt that could not be written after it: {error}"
    );
}

// ---------------------------------------------------------------------------
// R03, control half, and N4
// ---------------------------------------------------------------------------

#[test]
fn j4_r03_control_backpressure_never_delays_the_wall() {
    let fixture = Fixture::new();
    let sim = Sim::new(Scenario::Timed {
        exit_after: Duration::from_secs(20),
    });
    let log = Arc::clone(&sim.log);
    let started = Instant::now();
    let outcome = fixture.run_with(
        sim,
        &["--profile", "tool", "--limit", "wall=1s"],
        real(),
        Control::FullNeverRead,
    );
    let elapsed = started.elapsed();
    let log = log.lock().unwrap();
    let released = log.released_at.expect("released");
    let (reason, at) = *log.stops.first().expect("the wall stopped the target");
    assert_eq!(reason, StopReason::WallExpiry);
    let late = at.duration_since(released);
    assert!(
        late < Duration::from_millis(1500),
        "the wall fired {late:?} after release behind a full control pipe"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the final control drain is bounded: {elapsed:?}"
    );
    assert_eq!(outcome.report.exit_code, 143, "{:?}", outcome.report.error);
}

#[test]
fn j4_r03_control_backpressure_counts_an_undelivered_terminal_frame() {
    let fixture = Fixture::new();
    let outcome = fixture.run_with(
        Sim::new(Scenario::Plain),
        &["--profile", "tool"],
        real(),
        Control::FullNeverRead,
    );
    assert_eq!(outcome.report.exit_code, 0, "{:?}", outcome.report.error);
    // prepared, exec_confirmed and settled were all sent into a full pipe
    // nobody read: none of them was delivered, and all three are counted.
    assert_eq!(
        outcome.report.control_dropped, 3,
        "every undelivered frame, the terminal one included, is counted"
    );
}

#[test]
fn j4_n4_a_queued_terminal_frame_is_delivered_once_the_reader_returns() {
    let fixture = Fixture::new();
    let outcome = fixture.run_with(
        Sim::new(Scenario::Plain),
        &["--profile", "tool"],
        real(),
        Control::FullReadAfter(Duration::from_millis(300)),
    );
    assert_eq!(outcome.report.exit_code, 0, "{:?}", outcome.report.error);
    let kinds: Vec<&Value> = outcome.frames.iter().map(|frame| &frame["kind"]).collect();
    assert_eq!(
        kinds,
        ["prepared", "exec_confirmed", "settled"],
        "queued frames reach a reader that returns within the drain budget"
    );
    assert_eq!(outcome.report.control_dropped, 0);
    assert!(outcome.torn_tail.is_empty(), "no frame is cut short");
}

/// N4: the loop polls the control sink, so a frame queued behind a full pipe
/// reaches a reader that returns while the run goes on, not only when the next
/// message happens to be sent or at the final drain.
#[test]
fn j4_n4_a_queued_frame_reaches_a_returning_reader_while_the_run_goes_on() {
    let fixture = Fixture::new();
    let outcome = fixture.run_with(
        Sim::new(Scenario::Timed {
            exit_after: Duration::from_millis(1500),
        }),
        &["--profile", "tool", "--limit", "wall=1h"],
        real(),
        Control::FullReadAfter(Duration::from_millis(200)),
    );
    assert_eq!(outcome.report.exit_code, 0, "{:?}", outcome.report.error);
    let kinds: Vec<&Value> = outcome.frames.iter().map(|frame| &frame["kind"]).collect();
    assert_eq!(kinds, ["prepared", "exec_confirmed", "settled"]);
    let early = outcome.finished_at.duration_since(outcome.arrivals[1]);
    assert!(
        early >= Duration::from_millis(800),
        "exec_confirmed reached the reader only {early:?} before the run ended: it waited for the \
         next send instead of the loop's poll"
    );
}

// ---------------------------------------------------------------------------
// D5's remainder: the first error is the reported one
// ---------------------------------------------------------------------------

fn lost(reason: &str) -> RunEvent {
    RunEvent::EvidenceLost {
        reason: reason.to_owned(),
        after_target_end: false,
    }
}

#[test]
fn j4_d5_a_second_evidence_loss_does_not_replace_the_reported_error() {
    let fixture = Fixture::new();
    let outcome = fixture.run(
        Sim::new(Scenario::Script(vec![
            RunEvent::ExecConfirmed,
            lost("the first loss"),
            lost("the second loss"),
            RunEvent::TargetSignaled { signal: 15 },
        ])),
        &["--profile", "tool", "--evidence", "best-effort"],
        real(),
    );
    let error = outcome.report.error.as_ref().expect("an error");
    assert_eq!(
        error.message, "the first loss",
        "the first cause is the reported error"
    );
}

#[test]
fn j4_d5_a_later_persistence_failure_does_not_replace_the_reported_error() {
    let fixture = Fixture::new();
    let faults = Arc::new(Faults::new(fixture.watch()).failing(
        Site::EnforcedReceipt,
        Fault::RenameError,
        None,
    ));
    let outcome = fixture.run(
        Sim::new(Scenario::Script(vec![
            lost("the loss before exec was confirmed"),
            RunEvent::ExecConfirmed,
            RunEvent::TargetSignaled { signal: 15 },
        ])),
        &["--profile", "tool", "--evidence", "best-effort"],
        faults,
    );
    let error = outcome.report.error.as_ref().expect("an error");
    assert_eq!(
        error.message, "the loss before exec was confirmed",
        "the first cause is the reported error, not the later persistence failure: {error}"
    );
    assert_eq!(outcome.report.exit_code, 1);
}

// ---------------------------------------------------------------------------
// S9: every test seam in force is recorded
// ---------------------------------------------------------------------------

/// Set in the environment of the child that runs [`seam_child_helper`].
const SEAM_HELPER: &str = "OURO_J4_SEAM_HELPER";

/// Runs one simulated `tool` attempt in this (child) process, whose
/// environment the parent chose, and prints its receipt and jail state.
#[test]
#[ignore = "child helper invoked by j4_s9_every_test_seam_in_force_is_recorded"]
fn seam_child_helper() {
    if std::env::var_os(SEAM_HELPER).is_none() {
        return;
    }
    let fixture = Fixture::new();
    let outcome = fixture.run(Sim::new(Scenario::Plain), &["--profile", "tool"], real());
    let receipt = serde_json::to_value(outcome.report.receipt.expect("a receipt")).unwrap();
    let state: Value =
        serde_json::from_slice(&std::fs::read(fixture.attempt().join("jail-state.json")).unwrap())
            .unwrap();
    println!(
        "SEAM-RESULT {}",
        serde_json::json!({"receipt": receipt, "state": state})
    );
}

fn seam_child(seams: &[(&str, &str)]) -> Value {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "seam_child_helper", "--ignored", "--nocapture"]);
    command.env(SEAM_HELPER, "1");
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("OURO_JAIL_TEST_") {
            command.env_remove(name);
        }
    }
    for (name, value) in seams {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find_map(|line| line.strip_prefix("SEAM-RESULT "))
        .unwrap_or_else(|| {
            panic!(
                "the helper printed no result: {stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    serde_json::from_str(line).unwrap()
}

#[test]
fn j4_s9_every_test_seam_in_force_is_recorded() {
    // Values that change nothing in this run: the mediation queue only
    // matters to `agent`, the trace cap can only shrink and this one does
    // not, and the last name is one no build knows yet: the record must not
    // depend on a list of known seams.
    let seams = [
        ("OURO_JAIL_TEST_MEDIATION_QUEUE", "7"),
        ("OURO_JAIL_TEST_TRACE_CAP", "67108864"),
        ("OURO_JAIL_TEST_NOT_YET_INVENTED", "any value"),
    ];
    let expected: serde_json::Map<String, Value> = seams
        .iter()
        .map(|(name, value)| ((*name).to_owned(), Value::from(*value)))
        .collect();
    let with = seam_child(&seams);
    assert_eq!(
        with["receipt"]["lifetime"]["native"]["details"]["test_seams"],
        Value::Object(expected.clone()),
        "S9: the receipt names every OURO_JAIL_TEST_* variable set: {:#}",
        with["receipt"]["lifetime"]["native"]
    );
    assert_eq!(
        with["state"]["test_seams"],
        Value::Object(expected),
        "and so does jail state"
    );
    common::check_receipt(&with["receipt"]).unwrap();

    let without = seam_child(&[]);
    assert!(
        without["receipt"]["lifetime"]["native"]["details"]
            .get("test_seams")
            .is_none(),
        "a run with no seam records none: {:#}",
        without["receipt"]["lifetime"]["native"]
    );
    assert!(without["state"].get("test_seams").is_none());
}

// ---------------------------------------------------------------------------
// J4 wave 3 (W3-R): the records review's findings P1 to P6
// ---------------------------------------------------------------------------

/// `jail.json`'s revision, phase and bytes.
fn jail_json(attempt: &Path) -> (u64, String, Vec<u8>) {
    let bytes = std::fs::read(attempt.join("jail.json")).expect("jail.json");
    let value: Value = serde_json::from_slice(&bytes).expect("jail.json parses");
    (
        value["revision"].as_u64().unwrap(),
        value["phase"].as_str().unwrap().to_owned(),
        bytes,
    )
}

/// Waits, at most `within`, until the attempt root holds no temporary file:
/// a released step's replacement has either landed or been cleaned up.
/// Returns whether it got there.
fn temp_files_gone(attempt: &Path, within: Duration) -> bool {
    let dir = state::AttemptDir::from_root(attempt.to_path_buf());
    let until = Instant::now() + within;
    loop {
        if state::leftover_temp_files(&dir).unwrap().is_empty() {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// P1 (a). §13.3: "On failure or stall, stop the child with cause
/// `state_write_failed`, keep the transition unacknowledged, leave the
/// receipt at its last persisted phase, and do not start abandoned work
/// later." The enforced receipt's file sync stalls past the budget and then
/// completes, as a slow disk does. The worker used to check whether its
/// waiter gave up only before a job started, and a whole replacement is one
/// job, so the rename after the sync landed long after the supervisor had
/// returned. Abandoned work stops at the next step boundary.
#[test]
fn j4_w3_p1a_abandoned_persistence_stops_at_the_next_step() {
    let fixture = Fixture::new();
    let (faults, stall) = stalled(&fixture, Site::EnforcedReceipt);
    let outcome = fixture.run(
        Sim::new(Scenario::Timed {
            exit_after: Duration::from_secs(60),
        }),
        &["--profile", "tool"],
        faults.clone(),
    );
    assert_eq!(outcome.report.exit_code, 1, "{:?}", outcome.report.error);
    let attempt = fixture.attempt();
    let (revision, phase, bytes) = jail_json(&attempt);
    assert_eq!(phase, "prepared", "the enforced receipt never persisted");
    release(&stall);
    // The released sync completes; what the worker does next is either the
    // abandoned rename (the defect) or the removal of its temporary file.
    assert!(
        temp_files_gone(&attempt, Duration::from_secs(10)),
        "the released replacement neither landed nor cleaned up"
    );
    std::thread::sleep(Duration::from_millis(200));
    let (later_revision, later_phase, later_bytes) = jail_json(&attempt);
    assert!(
        later_bytes == bytes,
        "abandoned work landed after the supervisor gave up on it and returned: jail.json went \
         from revision {revision} {phase} to revision {later_revision} {later_phase}"
    );
    faults.finish("p1a at the end");
    let violations = faults.seen(|seen| seen.violations.clone());
    assert!(violations.is_empty(), "{violations:#?}");
}

/// P1 (b). The terminal receipt's rename stalls past the budget and then
/// completes. A rename in progress in the kernel cannot be abandoned, so the
/// lease is what keeps anyone else from writing the attempt's records
/// meanwhile: it is never released while persistence work is in flight. It
/// used to be unlocked as the run returned, so a `gc` in that window resumed
/// the pending vendor-state cleanup and wrote the next revision, and then
/// the supervisor's late rename landed a different receipt with the same
/// revision.
#[test]
fn j4_w3_p1b_the_lease_is_kept_while_persistence_is_in_flight() {
    let fixture = Fixture::new();
    let (faults, stall) = stalled_at(
        &fixture,
        Site::TerminalReceipt,
        StallAt::Rename,
        AfterStall::Complete,
    );
    let outcome = fixture.run(
        Sim::new(Scenario::Plain),
        &["--profile", "tool", "--launch", "plain"],
        faults.clone(),
    );
    assert_eq!(outcome.report.exit_code, 1, "{:?}", outcome.report.error);
    let attempt = fixture.attempt();
    let probe = state::Lease::probe_existing(&attempt.join("jail.lock")).unwrap();
    let held = matches!(probe, state::LeaseProbe::Held);
    drop(probe);
    let (before, before_phase, before_bytes) = jail_json(&attempt);
    let gc = fixture.gc(real());
    let (by_gc, gc_phase, gc_bytes) = jail_json(&attempt);
    release(&stall);
    assert!(
        temp_files_gone(&attempt, Duration::from_secs(10)),
        "the released rename never finished"
    );
    let (landed, landed_phase, landed_bytes) = jail_json(&attempt);
    assert!(
        held,
        "the lease was free while the terminal receipt's rename was still in flight"
    );
    assert_eq!(
        gc_bytes,
        before_bytes,
        "gc rewrote the receipt (revision {before} {before_phase} -> {by_gc} {gc_phase}) while \
         the supervisor's write was in flight: {:?}",
        gc.entries
            .iter()
            .map(|entry| (&entry.action, &entry.reason))
            .collect::<Vec<_>>()
    );
    assert!(
        !(landed == by_gc && landed_bytes != gc_bytes),
        "revision {landed} ({landed_phase}) was used for two different receipts"
    );
    faults.finish("p1b at the end");
    let violations = faults.seen(|seen| seen.violations.clone());
    assert!(violations.is_empty(), "{violations:#?}");
}

/// The simulated platform, binding a proxy socket as the Linux platform does
/// for a proxy-mode profile (it records the node's identity in the hand-off).
#[derive(Clone)]
struct SockSim(Sim);

impl Platform for SockSim {
    fn owner_identity(&self) -> Option<OwnerIdentity> {
        self.0.owner_identity()
    }
    fn identity(&self) -> PlatformIdentity {
        self.0.identity()
    }
    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        self.0.probe(plan)
    }
    fn prepare(
        &self,
        plan: PreparedPlan,
        _: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        let proxy = plan
            .proxy
            .as_ref()
            .expect("a proxy-mode profile has a proxy directory");
        let _ = proxy.socket.set(state::ProxySocketIdentity {
            dev: 1,
            ino: 2,
            ctime: (3, 4),
        });
        Ok(Box::new(SimPrepared(self.0.clone())))
    }
}

/// P2. A failed proxy-socket record (P3, `agent`) refused before the
/// boundary was applied to the record, but the teardown's verified tree was
/// copied in: a refused receipt with boundary `pending` and a verified tree,
/// which the receipt schema rejects. The refusal after setup reports the
/// boundary it tore down (§13.2 row 4).
#[test]
fn j4_w3_p2_a_failed_proxy_socket_record_writes_a_valid_refused_receipt() {
    let fixture = Fixture::new();
    // The proxy directory's registration and identity come first (0, 1).
    let faults = Arc::new(
        Faults::new(fixture.watch())
            .failing(Site::LaunchState, Fault::Enospc, None)
            .at_nth(2),
    );
    let ctx = supervisor::Context {
        platform: Box::new(SockSim(Sim::new(Scenario::Plain))),
        ..fixture.context(Sim::new(Scenario::Plain))
    };
    let args = fixture.args(&["--profile".to_owned(), "agent".to_owned()]);
    let report = state::with_persist_io(faults.clone(), || supervisor::run(&ctx, &args));
    assert!(
        faults.seen(|seen| seen.fired),
        "the socket record never failed"
    );
    let state_file: Value =
        serde_json::from_slice(&std::fs::read(fixture.attempt().join("jail-state.json")).unwrap())
            .unwrap();
    assert!(
        state_file["proxy_dir"]["socket"].is_null(),
        "the failed write was the socket record: {state_file:#}"
    );
    assert_eq!(report.exit_code, 125, "{:?}", report.error);
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(fixture.attempt().join("jail.json")).unwrap())
            .unwrap();
    if let Err(error) = common::check_receipt(&receipt) {
        panic!("the refused receipt fails its contract: {error}\n{receipt:#}");
    }
    assert_eq!(receipt["phase"], "refused");
    assert_eq!(receipt["outcome"]["error"]["code"], "state_write_failed");
    assert_eq!(
        receipt["lifetime"]["boundary"], "pid_namespace",
        "the refusal came after setup, and names the boundary it tore down: {:#}",
        receipt["lifetime"]
    );
    assert_eq!(receipt["lifetime"]["tree_empty"], true);
    faults.finish("p2 at the end");
    let violations = faults.seen(|seen| seen.violations.clone());
    assert!(violations.is_empty(), "{violations:#?}");
}

/// P2, the fault matrix extended to every P3 write, not only the first:
/// vendor state's registration, its identity and the staged credentials
/// (`--launch`), and the proxy directory's registration, its identity, the
/// socket node and the removal record (`agent`). Each is failed under every
/// fault, and the replacement after the last is checked never to happen, so
/// a P3 write added later is noticed here.
#[test]
fn j4_w3_p2_every_launch_state_write_under_every_fault_leaves_valid_records() {
    // (proxy, the writes before exec, the writes after it)
    let mut problems = Vec::new();
    for (proxy, before_exec, after_exec) in [(false, 3, 0), (true, 3, 1)] {
        let writes = before_exec + after_exec;
        for nth in 0..=writes {
            for fault in Fault::ALL {
                let label = format!(
                    "j4_w3_launch_state_{}_{nth}_{}",
                    if proxy { "proxy" } else { "vendor" },
                    fault.name()
                );
                let fixture = Fixture::new();
                let faults = Arc::new(
                    Faults::new(fixture.watch())
                        .failing(Site::LaunchState, fault, None)
                        .at_nth(nth),
                );
                let extra = fixture.extra.display().to_string();
                let mut flags = vec!["--receipt", extra.as_str()];
                flags.extend(if proxy {
                    ["--profile", "agent"]
                } else {
                    ["--launch", "plain"]
                });
                let sim = Sim::new(Scenario::Plain);
                let platform: Box<dyn Platform> = if proxy {
                    Box::new(SockSim(sim.clone()))
                } else {
                    Box::new(sim.clone())
                };
                let outcome = fixture.run_on(platform, &flags, faults.clone());
                faults.finish(&format!("{label} at the end"));
                let (fired, phase_at_fault, violations) = faults.seen(|seen| {
                    (
                        seen.fired,
                        seen.phase_at_fault.clone(),
                        seen.violations.clone(),
                    )
                });
                if nth == writes {
                    if fired {
                        problems.push(format!(
                            "{label}: a P3 write after the {writes} this test knows"
                        ));
                    }
                    // One fault is enough to show the list is complete.
                    break;
                }
                if !fired {
                    problems.push(format!("{label}: the fault was never injected"));
                }
                problems.extend(violations);
                let exit_code = if nth < before_exec { 125 } else { 1 };
                if nth < before_exec && rank(phase_at_fault.as_deref()) > 0 {
                    problems.push(format!(
                        "{label}: jail.json was already {phase_at_fault:?} at a write before \
                         preparation completed"
                    ));
                }
                if outcome.report.exit_code != exit_code {
                    problems.push(format!(
                        "{label}: exit code {} (error {:?}), S5 wants {exit_code}",
                        outcome.report.exit_code,
                        outcome.report.error.as_ref().map(ToString::to_string),
                    ));
                }
                problems.extend(acknowledged_only_what_persisted(&label, &outcome, &faults));
                for dir in fixture.watch().attempt_dirs() {
                    let leftover =
                        state::leftover_temp_files(&state::AttemptDir::from_root(dir)).unwrap();
                    if !leftover.is_empty() {
                        problems.push(format!("{label}: temporary files left: {leftover:?}"));
                    }
                }
                problems.extend(gc_keeps_everything(&label, &fixture, &faults));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// When the simulated target ended and when the supervisor went after the
/// rest of its tree.
#[derive(Clone, Default)]
struct Times {
    target_exit: Arc<Mutex<Option<Instant>>>,
    wait_tree: Arc<Mutex<Option<Instant>>>,
}

#[derive(Clone)]
struct ExitSim {
    sim: Sim,
    times: Times,
}

impl Platform for ExitSim {
    fn owner_identity(&self) -> Option<OwnerIdentity> {
        self.sim.owner_identity()
    }
    fn identity(&self) -> PlatformIdentity {
        self.sim.identity()
    }
    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        self.sim.probe(plan)
    }
    fn prepare(&self, _: PreparedPlan, _: Sinks) -> Result<Box<dyn PreparedExecution>, JailError> {
        Ok(Box::new(ExitPrepared(self.clone())))
    }
}

struct ExitPrepared(ExitSim);

impl PreparedExecution for ExitPrepared {
    fn boundary(&self) -> BoundaryIdentity {
        SimPrepared(self.0.sim.clone()).boundary()
    }
    fn applied(&self) -> Option<ouro_jail::records::Applied> {
        SimPrepared(self.0.sim.clone()).applied()
    }
    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, JailError> {
        Ok(Box::new(ExitRunning {
            times: self.0.times.clone(),
            step: 0,
        }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown {
            tree: Some(verified_tree()),
        })
    }
}

/// Exec confirmed, then the target exits at once (as `none` reports a short
/// target), leaving whatever descendants it started for `wait_tree` to end.
struct ExitRunning {
    times: Times,
    step: usize,
}

impl RunningExecution for ExitRunning {
    fn wait(&mut self, _: Deadline) -> RunEvent {
        self.step += 1;
        if self.step == 1 {
            return RunEvent::ExecConfirmed;
        }
        *self.times.target_exit.lock().unwrap() = Some(Instant::now());
        RunEvent::TargetExited { code: 0 }
    }
    fn request_stop(&mut self, _: StopReason) {}
    fn wait_tree(&mut self, _: Duration) -> TreeObservation {
        *self.times.wait_tree.lock().unwrap() = Some(Instant::now());
        verified_tree()
    }
    fn observer_summary(&mut self) -> Option<CoverageSummary> {
        None
    }
}

/// A disk that makes progress, slowly: every step of the enforced receipt
/// takes a second (never five without progress, so never a stall).
struct SlowEnforced;

impl SlowEnforced {
    fn slow(site: Site) {
        if site == Site::EnforcedReceipt {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

impl PersistIo for SlowEnforced {
    fn create_new(&self, site: Site, path: &Path) -> std::io::Result<std::fs::File> {
        Self::slow(site);
        state::RealIo.create_new(site, path)
    }
    fn write(&self, site: Site, file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<usize> {
        Self::slow(site);
        state::RealIo.write(site, file, bytes)
    }
    fn sync_file(&self, site: Site, file: &std::fs::File) -> std::io::Result<()> {
        Self::slow(site);
        state::RealIo.sync_file(site, file)
    }
    fn rename(&self, site: Site, from: &Path, to: &Path) -> std::io::Result<()> {
        Self::slow(site);
        state::RealIo.rename(site, from, to)
    }
    fn sync_dir(&self, site: Site, dir: &Path) -> std::io::Result<()> {
        Self::slow(site);
        state::RealIo.sync_dir(site, dir)
    }
}

/// P3. §8.1 step 8: "Target exit triggers termination of remaining attempt
/// descendants"; §13.3: "Do not wait forever for a writer while descendants
/// continue running." The supervisor used to wait for the receipts still with
/// the persistence worker before it ended the tree, so under `none` a slow
/// disk kept the target's descendants running for as long as the enforced
/// receipt took (30 s against a 2 s wall in the review). The tree is ended
/// first; the receipts are still acknowledged in order before the terminal
/// message.
#[test]
fn j4_w3_p3_the_tree_is_ended_without_waiting_for_persistence() {
    let fixture = Fixture::new();
    let times = Times::default();
    let ctx = supervisor::Context {
        platform: Box::new(ExitSim {
            sim: Sim::new(Scenario::Plain),
            times: times.clone(),
        }),
        ..fixture.context(Sim::new(Scenario::Plain))
    };
    let (reader, writer) = std::io::pipe().unwrap();
    let args = fixture.args(&[
        "--profile".to_owned(),
        "tool".to_owned(),
        "--limit".to_owned(),
        "wall=2s".to_owned(),
        "--control-fd".to_owned(),
        writer.into_raw_fd().to_string(),
    ]);
    let collector = std::thread::spawn(move || {
        let mut text = String::new();
        let mut reader = reader;
        reader.read_to_string(&mut text).unwrap();
        text
    });
    let report = state::with_persist_io(Arc::new(SlowEnforced), || supervisor::run(&ctx, &args));
    let frames: Vec<Value> = collector
        .join()
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let exit = times
        .target_exit
        .lock()
        .unwrap()
        .expect("the target exited");
    let tree = times.wait_tree.lock().unwrap().expect("the tree was ended");
    let delay = tree.saturating_duration_since(exit);
    assert!(
        delay < Duration::from_millis(500),
        "the rest of the tree was left running {delay:?} after the target exited, while the \
         supervisor waited for a receipt write"
    );
    assert_eq!(report.exit_code, 0, "{:?}", report.error);
    let kinds: Vec<&Value> = frames.iter().map(|frame| &frame["kind"]).collect();
    assert_eq!(
        kinds,
        ["prepared", "exec_confirmed", "settled"],
        "the enforced receipt is still acknowledged, in order, before the terminal message"
    );
}

/// Loss review, finding 5: a seam set twice in the environment was recorded
/// with its last value, while `getenv` (and so every consumer) applies the
/// first. The record says what the consumers read.
#[test]
fn j4_w3_a_seam_set_twice_is_recorded_with_the_value_getenv_returns() {
    let recorded = state::test_seams_in([
        (
            "OURO_JAIL_TEST_TRACER_INFLIGHT".into(),
            std::ffi::OsString::from("1"),
        ),
        ("PATH".into(), "/usr/bin".into()),
        (
            "OURO_JAIL_TEST_TRACER_INFLIGHT".into(),
            std::ffi::OsString::from("16384"),
        ),
    ])
    .expect("a seam is set");
    assert_eq!(
        recorded,
        serde_json::json!({"OURO_JAIL_TEST_TRACER_INFLIGHT": "1"}),
        "the first entry is the one getenv returns"
    );
}
