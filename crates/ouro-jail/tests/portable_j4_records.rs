//! J4 wave 0, records: the supervisor's receipts, `gc` and canonical bytes.
//!
//! - D3 (§7, §14.2): `gc`, dry run or not, never creates `jail.lock` for an
//!   attempt root that has none, so a pre-created managed root stays
//!   claimable, and a dry run changes nothing on disk.
//!
//! Portable: the platform is simulated, the filesystem is real.

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use clap::Parser as _;
use jsonschema::{Registry, Resource, Validator};
use ouro_jail::capability::{Capability, CapabilityScope, CapabilityStatus};
use ouro_jail::config::EnvSettings;
use ouro_jail::observer::CoverageSummary;
use ouro_jail::platform::{
    BoundaryIdentity, Deadline, OwnerIdentity, PlanRequest, Platform, PlatformIdentity,
    PreparedExecution, PreparedPlan, RunEvent, RunningExecution, Sinks, StopReason, Teardown,
    TreeObservation,
};
use ouro_jail::records::{NativeLifetime, Os, ProcessIdentity, ProcessRecord, rfc3339_utc};
use ouro_jail::state::{AttemptDir, AttemptId};
use ouro_jail::{cli, supervisor};
use serde_json::Value;

mod common;

// ---------------------------------------------------------------------------
// A scripted platform
// ---------------------------------------------------------------------------

/// What the simulated run reports, in order, once released.
#[derive(Clone, Default)]
struct Script {
    events: Vec<RunEvent>,
    /// Every `request_stop` the supervisor made, in order.
    stops: Arc<Mutex<Vec<StopReason>>>,
}

struct Simulated(Script);
struct Prepared(Script);
struct Running {
    events: VecDeque<RunEvent>,
    stops: Arc<Mutex<Vec<StopReason>>>,
}

impl Platform for Simulated {
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
                evidence_ref: Some("records simulation".into()),
            })
            .collect()
    }
    fn prepare(
        &self,
        _: PreparedPlan,
        _: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, ouro_jail::records::JailError> {
        Ok(Box::new(Prepared(self.0.clone())))
    }
}

impl PreparedExecution for Prepared {
    fn boundary(&self) -> BoundaryIdentity {
        BoundaryIdentity {
            boundary: "supervisor_cgroup".into(),
            verification_scope: "registered_boundary".into(),
            native: Some(NativeLifetime {
                os: Os::Linux,
                details: Default::default(),
            }),
            process: Some(ProcessRecord {
                pid: 4242,
                identity: ProcessIdentity {
                    kind: "linux_boot_start".into(),
                    value: Default::default(),
                },
            }),
            backend: Some("none".into()),
            backend_version: None,
        }
    }
    fn release(
        self: Box<Self>,
    ) -> Result<Box<dyn RunningExecution>, ouro_jail::records::JailError> {
        Ok(Box::new(Running {
            events: self.0.events.into(),
            stops: self.0.stops,
        }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, ouro_jail::records::JailError> {
        Ok(Teardown { tree: None })
    }
}

impl RunningExecution for Running {
    fn wait(&mut self, _: Deadline) -> RunEvent {
        self.events
            .pop_front()
            .unwrap_or(RunEvent::TargetExited { code: 0 })
    }
    fn request_stop(&mut self, reason: StopReason) {
        self.stops.lock().unwrap().push(reason);
    }
    fn wait_tree(&mut self, _: Duration) -> TreeObservation {
        TreeObservation {
            tree_empty: Some(true),
            verified_at: Some(SystemTime::now()),
            verification_scope: "registered_boundary".into(),
            integrity: "verified".into(),
        }
    }
    fn observer_summary(&mut self) -> Option<CoverageSummary> {
        None
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
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

impl Fixture {
    fn new() -> Fixture {
        let dir = common::private_tempdir();
        // Canonical, so that macOS's /var -> /private/var alias is not a symlink
        // on any no-follow walk.
        let root = dir.path().canonicalize().unwrap();
        let fixture = Fixture {
            config: root.join("config"),
            data: root.join("data"),
            workspace: root.join("workspace"),
            root,
            _root: dir,
        };
        for path in [&fixture.config, &fixture.data, &fixture.workspace] {
            private_dir(path);
        }
        private_dir(&fixture.config.join("launch"));
        fixture
    }

    fn context(&self, script: Script) -> supervisor::Context {
        supervisor::Context {
            platform: Box::new(Simulated(script)),
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

    fn run_args(&self, flags: &[&str]) -> cli::RunArgs {
        let mut argv: Vec<String> = vec!["ouro-jail".into(), "run".into()];
        argv.push("--workspace".into());
        argv.push(self.workspace.display().to_string());
        argv.extend(flags.iter().map(|flag| (*flag).to_owned()));
        argv.push("--".into());
        argv.push("simulated-target".into());
        let cli::Command::Run(args) = cli::Cli::parse_from(argv).command else {
            unreachable!()
        };
        *args
    }

    fn run(&self, script: Script, flags: &[&str]) -> supervisor::RunReport {
        let args = self.run_args(flags);
        supervisor::run(&self.context(script), &args)
    }

    fn gc(&self, dry_run: bool) -> supervisor::GcReport {
        let report = supervisor::gc(
            &self.context(Script::default()),
            &cli::GcArgs {
                dry_run,
                json: false,
            },
        );
        match report {
            Ok(report) => report,
            Err(error) => panic!("gc must scan: {error}"),
        }
    }

    /// Pre-creates `<data>/attempts/<id>/` the way a managed owner reserving an
    /// attempt would: a private, empty directory and nothing jail-owned in it.
    fn reserve(&self, id: &str) -> AttemptDir {
        let id = AttemptId::parse(id).unwrap();
        let dir = AttemptDir::new(&self.data, &id);
        dir.create(&self.data).unwrap();
        dir
    }
}

fn receipt_validator() -> &'static Validator {
    static ONCE: std::sync::OnceLock<Validator> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/jail-v1");
        let mut resources = Vec::new();
        let mut receipt = None;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.ends_with(".schema.json") {
                continue;
            }
            let schema: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            if name == "jail-receipt.schema.json" {
                receipt = Some(schema.clone());
            }
            let id = schema["$id"].as_str().unwrap().to_owned();
            resources.push((id, Resource::from_contents(schema)));
        }
        let registry: &'static Registry = Box::leak(Box::new(
            Registry::new()
                .extend(resources)
                .unwrap()
                .prepare()
                .unwrap(),
        ));
        jsonschema::options()
            .with_registry(registry)
            .should_validate_formats(true)
            .build(&receipt.unwrap())
            .unwrap()
    })
}

fn valid_receipt(report: &supervisor::RunReport) -> Value {
    let receipt = serde_json::to_value(report.receipt.as_ref().expect("a receipt")).unwrap();
    let errors: Vec<String> = receipt_validator()
        .iter_errors(&receipt)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "the receipt fails its schema: {errors:?}\n{receipt:#}"
    );
    receipt
}

// ---------------------------------------------------------------------------
// D3: gc and the attempt lease file
// ---------------------------------------------------------------------------

mod d3 {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Write as _;
    use std::os::fd::IntoRawFd as _;
    use std::os::unix::fs::MetadataExt as _;

    use ouro_jail::state;

    // A byte-exact picture of a directory tree.

    /// `(kind, permission bits, size, mtime, content)` of one entry.
    type Entry = (&'static str, u32, u64, (i64, i64), Option<Vec<u8>>);

    /// Every entry below `root`, never following a symlink, with everything a
    /// write would change: presence, type, mode, size, mtime (a directory's
    /// changes when an entry is added or removed) and file bytes.
    fn picture(root: &Path) -> BTreeMap<PathBuf, Entry> {
        let mut out = BTreeMap::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            let kind = if metadata.file_type().is_symlink() {
                "symlink"
            } else if metadata.is_dir() {
                "dir"
            } else if metadata.is_file() {
                "file"
            } else {
                "other"
            };
            let content = (kind == "file").then(|| std::fs::read(&path).unwrap());
            if kind == "dir" {
                for entry in std::fs::read_dir(&path).unwrap() {
                    pending.push(entry.unwrap().path());
                }
            }
            out.insert(
                path.strip_prefix(root).unwrap().to_path_buf(),
                (
                    kind,
                    metadata.mode() & 0o7777,
                    metadata.len(),
                    (metadata.mtime(), metadata.mtime_nsec()),
                    content,
                ),
            );
        }
        out
    }

    const RESERVED: &str = "att_4d3a0000-0000-4000-8000-000000000003";

    /// §7: "An existing attempt root is acceptable only with validated
    /// ownership/permissions and no previous jail state or jail-owned
    /// artifacts." A managed owner that reserved a root must still be able to
    /// claim it after any number of `gc` passes, dry or not.
    #[test]
    fn j4_d3_a_pre_created_attempt_root_stays_claimable_after_gc() {
        let fixture = Fixture::new();
        let reserved = fixture.reserve(RESERVED);

        let dry = fixture.gc(true);
        let wet = fixture.gc(false);

        // The managed claim: `--attempt-id` with a gate that releases it.
        let policy = fixture.run_args(&["--profile", "none"]).policy;
        let digest = supervisor::resolve_plan(&fixture.context(Script::default()), &policy)
            .unwrap_or_else(|error| panic!("the plan resolves: {error}"))
            .resolved
            .digest;
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer
            .write_all(
                format!(
                    "{{\"schema\":\"ouro.jail.gate/1\",\"action\":\"release\",\
                 \"attempt_id\":\"{RESERVED}\",\"policy_digest\":\"{digest}\"}}\n"
                )
                .as_bytes(),
            )
            .unwrap();
        drop(writer);
        // The supervisor owns the gate descriptor from here (§6.1) and closes it.
        let gate = reader.into_raw_fd().to_string();
        let args = fixture.run_args(&[
            "--profile",
            "none",
            "--attempt-id",
            RESERVED,
            "--gate-fd",
            &gate,
        ]);
        let script = Script {
            events: vec![RunEvent::ExecConfirmed, RunEvent::TargetExited { code: 0 }],
            ..Script::default()
        };
        let report = supervisor::run(&fixture.context(script), &args);
        assert_eq!(
            report
                .error
                .as_ref()
                .map(|error| (error.code, error.message.clone())),
            None,
            "the reserved root must be claimable after gc"
        );
        let receipt = valid_receipt(&report);
        assert_eq!(receipt["attempt_id"], RESERVED);
        assert_eq!(receipt["phase"], "settled", "{receipt:#}");
        let claim: Value =
            serde_json::from_slice(&std::fs::read(reserved.state_path()).unwrap()).unwrap();
        assert_eq!(claim["attempt_id"], RESERVED, "the claim is this attempt's");

        // And gc said what it did: it retained an unclaimed root, it did not
        // report a failed cleanup for it.
        for (label, report) in [("dry run", &dry), ("gc", &wet)] {
            assert_eq!(report.entries.len(), 1, "{label}");
            assert_eq!(report.entries[0].attempt_id, RESERVED, "{label}");
            assert_eq!(
                report.entries[0].action, "retained",
                "{label}: {}",
                report.entries[0].reason
            );
            assert!(
                report.entries[0].reason.contains("no jail.lock"),
                "{label}: {}",
                report.entries[0].reason
            );
            assert!(
                report.incomplete.is_empty(),
                "{label}: {:?}",
                report.incomplete
            );
            assert_eq!(report.entries[0].proxy_dir, None, "{label}");
        }
    }

    /// §14.2: `gc --dry-run` "reports actions/reasons"; it removes, creates and
    /// rewrites nothing. The tree holds each kind of attempt root `gc` meets: a
    /// reserved one, a settled one, one whose supervisor died between taking the
    /// lease and claiming, and a name that is not an attempt id.
    #[test]
    fn j4_d3_gc_dry_run_changes_nothing_on_disk() {
        let fixture = Fixture::new();
        fixture.reserve(RESERVED);
        let settled = fixture.run(
            Script {
                events: vec![RunEvent::ExecConfirmed, RunEvent::TargetExited { code: 0 }],
                ..Script::default()
            },
            &["--profile", "none"],
        );
        assert_eq!(
            settled.exit_code,
            0,
            "{:?}",
            settled.error.map(|error| error.message)
        );
        let lease_only = fixture.reserve("att_4d3a0000-0000-4000-8000-000000000004");
        drop(state::Lease::acquire(&lease_only.lock_path()).unwrap());
        private_dir(&fixture.data.join("attempts").join("not-an-attempt"));

        let before = picture(&fixture.data);
        let report = fixture.gc(true);
        assert!(report.dry_run);
        assert_eq!(report.entries.len(), 4);
        let after = picture(&fixture.data);
        let changed: std::collections::BTreeSet<&PathBuf> = before
            .keys()
            .chain(after.keys())
            .filter(|path| before.get(*path) != after.get(*path))
            .collect();
        let kinds = |picture: &BTreeMap<PathBuf, Entry>| -> Vec<Option<&'static str>> {
            changed
                .iter()
                .map(|path| picture.get(*path).map(|entry| entry.0))
                .collect()
        };
        assert!(
            changed.is_empty(),
            "a dry run changed {changed:?}\nbefore: {:?}\nafter: {:?}",
            kinds(&before),
            kinds(&after),
        );
    }

    /// A root holding jail-owned artifacts but no `jail.lock` is not this tool's
    /// own layout (the lease precedes every claim); `gc` has no lease to take, so
    /// it touches nothing there and says why, rather than creating a lock.
    #[test]
    fn j4_d3_gc_never_creates_a_lock_beside_other_artifacts() {
        let fixture = Fixture::new();
        let reserved = fixture.reserve(RESERVED);
        private_file(&reserved.state_path(), b"{}");
        for dry_run in [true, false] {
            let before = picture(&fixture.data);
            let report = fixture.gc(dry_run);
            assert_eq!(picture(&fixture.data), before, "dry_run={dry_run}");
            assert_eq!(report.entries[0].action, "retained");
            assert!(
                report.entries[0].reason.contains("no lease protects")
                    && report.entries[0].reason.contains("jail-state.json"),
                "{}",
                report.entries[0].reason
            );
            assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
        }
    }

    /// The lease probe `gc` uses on an existing `jail.lock` still sees a live
    /// holder (§14.2: "Active locks ... are retained").
    #[test]
    fn j4_d3_gc_retains_an_attempt_whose_lease_is_held() {
        let fixture = Fixture::new();
        let reserved = fixture.reserve(RESERVED);
        let held = state::Lease::acquire(&reserved.lock_path())
            .unwrap()
            .expect("the lease is free");
        for dry_run in [true, false] {
            let report = fixture.gc(dry_run);
            assert_eq!(report.entries[0].action, "retained");
            assert!(
                report.entries[0].reason.contains("live supervisor"),
                "{}",
                report.entries[0].reason
            );
            assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
        }
        drop(held);
    }
}
