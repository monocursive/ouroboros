//! J3 launch profiles, credential staging and cleanup, portable part.
//!
//! These run natively on macOS and on Linux. Resolution is exercised through
//! the real `resolve_plan`; the attempt lifecycle through the real supervisor
//! over a simulated platform, so staging, the hand-off, refusal and cleanup
//! run against the real filesystem while the boundary is scripted. Every
//! credential here is a fixture file this test writes; none is an operator's.
//!
//! Acceptance rows: C01 (sources preserved, provenance without bytes, byte
//! paths lossless, unsafe `state_subdirs` and every `LD_*`/`DYLD_*` key
//! refuse), C02 (normal exit and refusal clean vendor state, an interrupted
//! cleanup resumes, symlinks cannot redirect deletion), P04's credential
//! sub-clause (FIFO, device, socket, symlink, directory and oversize sources
//! refuse before exec) and I02's data-only boundary for the bundled profiles.
//!
//! What this file does not prove: that a real bubblewrap boundary binds the
//! staged objects. `conformance_j3_credentials.rs` does that on Linux.

use std::collections::BTreeMap;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use clap::Parser as _;
use jsonschema::{Registry, Resource, Validator};
use ouro_jail::capability::{Capability, CapabilityScope, CapabilityStatus};
use ouro_jail::cli::{self, PolicyArgs};
use ouro_jail::config::EnvSettings;
use ouro_jail::credentials::LaunchHandoff;
use ouro_jail::platform::{
    BoundaryIdentity, Deadline, OwnerIdentity, PlanRequest, Platform, PlatformIdentity,
    PreparedExecution, PreparedPlan, RunEvent, RunningExecution, Sinks, StopReason, Teardown,
    TreeObservation,
};
use ouro_jail::policy::{EnvValue, ProfileName, RootToken};
use ouro_jail::records::{
    ErrorCode, JailError, NativeLifetime, Os, Receipt, Remediation, StateCleanup, rfc3339_utc,
};
use ouro_jail::{cleanup, launch_profile, supervisor};
use sha2::{Digest as _, Sha256};

mod common;

// ---------------------------------------------------------------------------
// Fixture layout
// ---------------------------------------------------------------------------

struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    data: PathBuf,
    workspace: PathBuf,
    creds: PathBuf,
    outside: PathBuf,
}

fn fixture_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

impl Fixture {
    fn new() -> Fixture {
        let dir = common::private_tempdir();
        // Canonical, so that macOS's /var -> /private/var alias is not a
        // symlink on a credential source's no-follow walk.
        let root = dir.path().canonicalize().unwrap();
        let fixture = Fixture {
            config: root.join("config"),
            data: root.join("data"),
            workspace: root.join("workspace"),
            creds: root.join("creds"),
            outside: root.join("outside"),
            root,
            _root: dir,
        };
        for path in [
            &fixture.config,
            &fixture.data,
            &fixture.workspace,
            &fixture.creds,
            &fixture.outside,
        ] {
            private_dir(path);
        }
        private_dir(&fixture.config.join("launch"));
        std::fs::write(fixture.outside.join("precious"), b"outside the attempt").unwrap();
        fixture
    }

    fn launch(&self, name: &str, text: &str) -> PathBuf {
        let path = self.config.join("launch").join(format!("{name}.toml"));
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn credential(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.creds.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn context(&self, platform: Box<dyn Platform>, home: Option<PathBuf>) -> supervisor::Context {
        supervisor::Context {
            platform,
            env_settings: EnvSettings {
                config_dir: Some(self.config.clone()),
                data_dir: Some(self.data.clone()),
                ..Default::default()
            },
            cwd: self.workspace.clone(),
            home,
            env_lookup: Box::new(|_| None),
        }
    }

    fn plan(&self, policy: PolicyArgs) -> Result<supervisor::Plan, JailError> {
        let ctx = self.context(Box::new(Sim::default()), Some(self.root.join("home")));
        supervisor::resolve_plan(&ctx, &policy)
    }

    fn run(&self, sim: Sim, flags: &[&str]) -> supervisor::RunReport {
        let mut argv: Vec<String> = vec!["ouro-jail".into(), "run".into()];
        argv.push("--workspace".into());
        argv.push(self.workspace.display().to_string());
        argv.extend(flags.iter().map(|flag| (*flag).to_owned()));
        argv.push("--".into());
        argv.push("simulated-target".into());
        let cli::Command::Run(args) = cli::Cli::parse_from(argv).command else {
            unreachable!()
        };
        let ctx = self.context(Box::new(sim), Some(self.root.join("home")));
        supervisor::run(&ctx, &args)
    }

    fn gc(&self, dry_run: bool) -> Result<supervisor::GcReport, JailError> {
        let ctx = self.context(Box::new(Sim::default()), None);
        supervisor::gc(
            &ctx,
            &cli::GcArgs {
                dry_run,
                json: false,
            },
        )
    }
}

fn launch_args(name: &str, workspace: &Path) -> PolicyArgs {
    PolicyArgs {
        launch: Some(name.to_owned()),
        workspace: Some(workspace.to_path_buf()),
        ..PolicyArgs::default()
    }
}

/// The refusal a resolution must produce (`Plan` has no `Debug`).
fn refused(result: Result<supervisor::Plan, JailError>, label: &str) -> JailError {
    match result {
        Ok(_) => panic!("{label}: resolution must refuse"),
        Err(error) => error,
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::from("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn attempt_dir(report: &supervisor::RunReport) -> PathBuf {
    report
        .receipt_path
        .as_ref()
        .expect("an attempt was allocated")
        .parent()
        .unwrap()
        .to_path_buf()
}

fn jail_state(report: &supervisor::RunReport) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(attempt_dir(report).join("jail-state.json")).unwrap())
        .unwrap()
}

fn receipt_json(report: &supervisor::RunReport) -> serde_json::Value {
    serde_json::to_value(report.receipt.as_ref().expect("a receipt")).unwrap()
}

// ---------------------------------------------------------------------------
// The checked-in schemas
// ---------------------------------------------------------------------------

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs/jail-v1")
        .canonicalize()
        .unwrap()
}

fn validators() -> &'static BTreeMap<String, Validator> {
    static ONCE: std::sync::OnceLock<BTreeMap<String, Validator>> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let mut schemas: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        for entry in std::fs::read_dir(specs_dir()).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(".schema.json") {
                schemas.insert(
                    stem.to_owned(),
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap(),
                );
            }
        }
        let pairs: Vec<(String, Resource)> = schemas
            .values()
            .map(|schema| {
                (
                    schema["$id"].as_str().unwrap().to_owned(),
                    Resource::from_contents(schema.clone()),
                )
            })
            .collect();
        let registry: &'static Registry = Box::leak(Box::new(
            Registry::new().extend(pairs).unwrap().prepare().unwrap(),
        ));
        schemas
            .into_iter()
            .map(|(name, schema)| {
                let validator = jsonschema::options()
                    .with_registry(registry)
                    .should_validate_formats(true)
                    .build(&schema)
                    .unwrap();
                (name, validator)
            })
            .collect()
    })
}

fn assert_schema(name: &str, value: &serde_json::Value) {
    let validator = &validators()[name];
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{name} rejects {value:#}: {errors:?}");
}

// ---------------------------------------------------------------------------
// A scripted platform: real staging and cleanup, scripted boundary
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum TreeEnd {
    #[default]
    Verified,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum TargetEnd {
    #[default]
    Exit0,
    ExecError,
}

/// What the simulated platform saw of the hand-off.
#[derive(Clone, Debug, Default)]
struct Seen {
    prepared: bool,
    vendor_path: Option<PathBuf>,
    /// `(id, dest, identity)` of each bind handle, as `fstat` reports it.
    binds: Vec<(String, String, (u64, u64))>,
}

type Activity = Arc<dyn Fn(&Path) + Send + Sync>;
/// `(relative path, bytes, permission bits)` of one staged object.
type Listed = (String, Vec<u8>, u32);
/// Makes one special source object at a path.
type Maker = Box<dyn Fn(&Path)>;
/// Undoes an obstruction.
type Undo = Box<dyn Fn() + Send>;

#[derive(Clone, Default)]
struct Sim {
    /// The network mode the scripted boundary reports as applied.
    network: Arc<Mutex<String>>,
    tree: TreeEnd,
    target: TargetEnd,
    release_fails: bool,
    /// Whether a failed release reports a verified teardown.
    release_teardown_verified: bool,
    /// Whether a failed release reports a teardown that lost integrity.
    release_teardown_lost: bool,
    /// When set, the data directory in whose (single) attempt a
    /// `vendor-state` directory appears during probing: an operator process
    /// racing the claim.
    plant_vendor_state: Option<PathBuf>,
    /// Report no applied mechanisms (the `none` profile applies none).
    unapplied: bool,
    /// What the "child" does in vendor state, given its host path.
    activity: Option<Activity>,
    seen: Arc<Mutex<Seen>>,
}

fn verified_tree() -> TreeObservation {
    TreeObservation {
        tree_empty: Some(true),
        verified_at: Some(SystemTime::now()),
        verification_scope: "attempt_tree".into(),
        integrity: "verified".into(),
    }
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
        if let Some(data) = &self.plant_vendor_state {
            let attempt = std::fs::read_dir(data.join("attempts"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            std::fs::create_dir(attempt.join("vendor-state")).unwrap();
            std::fs::write(attempt.join("vendor-state/precious"), b"not this attempt's").unwrap();
        }
        plan.requirements
            .iter()
            .map(|name| Capability {
                name: name.clone(),
                status: CapabilityStatus::Available,
                scope: CapabilityScope::Tree,
                mechanism: Some("simulation".into()),
                reason_code: Some("ok".into()),
                measured_at: Some(rfc3339_utc(SystemTime::now())),
                evidence_ref: Some("J3 launch simulation".into()),
            })
            .collect()
    }
    fn prepare(
        &self,
        plan: PreparedPlan,
        _: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        plan.request
            .snapshot
            .network
            .mode
            .clone_into(&mut self.network.lock().unwrap());
        let mut seen = self.seen.lock().unwrap();
        seen.prepared = true;
        if let Some(handoff) = &plan.launch {
            observe_handoff(handoff, &mut seen);
        }
        drop(seen);
        if let (Some(activity), Some(handoff)) = (&self.activity, &plan.launch)
            && let Some(vendor) = &handoff.vendor_state
        {
            activity(&vendor.host_path);
        }
        Ok(Box::new(SimPrepared { sim: self.clone() }))
    }
}

fn observe_handoff(handoff: &LaunchHandoff, seen: &mut Seen) {
    use std::os::fd::AsFd as _;
    seen.vendor_path = handoff
        .vendor_state
        .as_ref()
        .map(|vendor| vendor.host_path.clone());
    for bind in &handoff.binds {
        let stat = ouro_jail::state::anchored::fstat(bind.fd.as_fd()).unwrap();
        seen.binds
            .push((bind.id.clone(), bind.dest.to_display(), stat.identity()));
    }
}

struct SimPrepared {
    sim: Sim,
}

impl PreparedExecution for SimPrepared {
    fn boundary(&self) -> BoundaryIdentity {
        BoundaryIdentity {
            boundary: "pid_namespace".into(),
            verification_scope: "attempt_tree".into(),
            native: Some(NativeLifetime {
                os: Os::Linux,
                details: Default::default(),
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
        if self.sim.unapplied {
            return None;
        }
        // A scripted application with the shape the receipt contract requires
        // of an enforced boundary; the mechanisms say they are simulated.
        use ouro_jail::records::{Applied, AppliedFilesystem, AppliedNetwork, AppliedSyscalls};
        Some(Applied {
            filesystem: Some(AppliedFilesystem {
                mechanism: "simulation".into(),
                protected_coverage: "none".into(),
                mounts: Vec::new(),
            }),
            network: AppliedNetwork {
                mode: self.sim.network.lock().unwrap().clone(),
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
        if self.sim.release_fails {
            return Err(JailError::new(
                ErrorCode::BackendUnavailable,
                ouro_jail::records::ErrorStage::Released,
                Remediation::Retry,
                "simulated release failure",
            ));
        }
        Ok(Box::new(SimRunning {
            sim: self.sim,
            step: 0,
        }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown {
            tree: Some(verified_tree()),
        })
    }
    fn release_reporting_teardown(
        self: Box<Self>,
    ) -> Result<Box<dyn RunningExecution>, Box<ouro_jail::platform::ReleaseFailure>> {
        let verified = self.sim.release_teardown_verified;
        let lost = self.sim.release_teardown_lost;
        self.release().map_err(|error| {
            let tree = if lost {
                Some(TreeObservation {
                    tree_empty: None,
                    verified_at: None,
                    verification_scope: "attempt_tree".into(),
                    integrity: "lost".into(),
                })
            } else {
                verified.then(verified_tree)
            };
            Box::new(ouro_jail::platform::ReleaseFailure {
                error,
                teardown: tree.map(|tree| Teardown { tree: Some(tree) }),
            })
        })
    }
}

struct SimRunning {
    sim: Sim,
    step: u8,
}

impl RunningExecution for SimRunning {
    fn wait(&mut self, _: Deadline) -> RunEvent {
        self.step += 1;
        match (self.sim.target, self.step) {
            (TargetEnd::ExecError, _) => RunEvent::ExecError {
                errno: "ENOENT".into(),
            },
            (TargetEnd::Exit0, 1) => RunEvent::ExecConfirmed,
            (TargetEnd::Exit0, _) => RunEvent::TargetExited { code: 0 },
        }
    }
    fn request_stop(&mut self, _: StopReason) {}
    fn wait_tree(&mut self, _: Duration) -> TreeObservation {
        match self.sim.tree {
            TreeEnd::Verified => verified_tree(),
            TreeEnd::Unknown => TreeObservation {
                tree_empty: None,
                verified_at: None,
                verification_scope: "attempt_tree".into(),
                integrity: "pending".into(),
            },
        }
    }
    fn observer_summary(&mut self) -> Option<ouro_jail::observer::CoverageSummary> {
        None
    }
}

// A two-credential agent profile over fixture files.
fn agent_profile(fixture: &Fixture, auth: &Path, config: &Path) {
    fixture.launch(
        "fixture",
        &format!(
            r#"
name = "fixture"
jail = "agent"
state_var = "FIXTURE_HOME"
home_is_state = true
state_subdirs = ["sessions/deep", "cache"]

[environment]
FIXTURE_MODE = "batch"
FIXTURE_CACHE = {{ state = "cache" }}

[credentials.auth]
source = "{}"
dest = "auth.json"
mode = "copy_rw"

[credentials.config]
source = "{}"
dest = "conf/config.toml"
mode = "bind_ro"

[network]
allow = ["api.example.test:443"]
"#,
            auth.display(),
            config.display()
        ),
    );
}

// ---------------------------------------------------------------------------
// Bundled data (I02: agent names live only in data)
// ---------------------------------------------------------------------------

#[test]
fn i02_the_bundled_profiles_are_valid_experimental_data_for_the_agent_jail() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles/launch");
    let mut names: Vec<String> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["claude.toml", "codex.toml", "opencode.toml"]);
    for name in &names {
        let text = std::fs::read_to_string(directory.join(name)).unwrap();
        assert!(
            text.starts_with("# EXPERIMENTAL"),
            "{name} must say it is experimental"
        );
        let stem = name.strip_suffix(".toml").unwrap();
        let profile =
            launch_profile::parse(&text, stem, b"/operator/config/launch", Some(b"/home/op"))
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(profile.jail, ProfileName::Agent, "{name}");
        assert!(profile.needs_vendor_state(), "{name}");
        for credential in &profile.credentials {
            assert!(
                credential.source.as_bytes().starts_with(b"/home/op/"),
                "{name}: sources are the node's own files beneath the operator home"
            );
        }
        // The bundled data declares credentials, so §6.1 keeps it off `tool`.
        assert!(launch_profile::check_jail_permits(ProfileName::Tool, &profile).is_err());
    }
}

#[test]
fn i02_the_runtime_never_embeds_or_discovers_the_bundled_profiles() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let text = std::fs::read_to_string(&path).unwrap();
                assert!(
                    !text.contains("profiles/launch/") || path.ends_with("launch_profile.rs"),
                    "{} refers to the bundled profile directory",
                    path.display()
                );
                assert!(
                    !text.contains("include_str!(\"../profiles"),
                    "{} embeds bundled profile data",
                    path.display()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Resolution (C01 validation, §6.1, §6.2, §12)
// ---------------------------------------------------------------------------

#[test]
fn c01_a_launch_profile_resolves_into_the_snapshot_and_validates_against_the_schema() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"{\"token\":\"fixture-secret-1\"}");
    let config = fixture.credential("config.toml", b"model = \"fixture\"\n");
    agent_profile(&fixture, &auth, &config);
    let plan = fixture
        .plan(launch_args("fixture", &fixture.workspace))
        .expect("resolves");
    let snapshot = &plan.resolved.snapshot;
    assert_eq!(
        snapshot.profile,
        ProfileName::Agent,
        "the launch default jail"
    );
    assert!(snapshot.roots.vendor_state.is_some());
    let launch = snapshot.launch.as_ref().expect("the launch field group");
    let ids: Vec<&str> = launch.credentials.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["auth", "config"]);
    assert_eq!(
        launch.credentials[0].source.as_bytes(),
        auth.as_os_str().as_bytes()
    );
    let binding = |name: &str| {
        snapshot
            .environment
            .bindings
            .iter()
            .find(|binding| binding.name == name)
            .unwrap_or_else(|| panic!("{name} is bound"))
            .value
            .clone()
    };
    for name in ["FIXTURE_HOME", "HOME", "FIXTURE_CACHE"] {
        assert!(
            matches!(binding(name), EnvValue::Path(ref r) if r.root == RootToken::VendorState),
            "{name} points at vendor state, never a host path"
        );
    }
    assert!(
        plan.resolved
            .requirements
            .iter()
            .any(|requirement| requirement == "credential_staging")
    );
    assert!(
        plan.resolved
            .grants
            .iter()
            .any(|grant| grant.kind == "allow_host")
    );
    let canonical = snapshot.to_canonical_value().unwrap();
    assert_schema("policy-snapshot", &canonical);
}

#[test]
fn c01_equivalent_launch_files_share_a_digest_and_semantic_changes_do_not() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let first = fixture
        .plan(launch_args("fixture", &fixture.workspace))
        .unwrap()
        .resolved
        .digest;
    // The same semantics, written in another order with other spelling:
    // keys and tables reordered, a source spelled through `..` and `.`.
    fixture.launch(
        "fixture",
        &format!(
            r#"
home_is_state = true
state_subdirs = ["cache", "sessions/deep"]
state_var = "FIXTURE_HOME"
jail = "agent"
name = "fixture"

[network]
allow = ["api.example.test:443"]

[credentials.config]
mode = "bind_ro"
dest = "conf/config.toml"
source = "{}/../creds/./config.toml"

[credentials.auth]
mode = "copy_rw"
dest = "auth.json"
source = "{}"

[environment]
FIXTURE_CACHE = {{ state = "cache" }}
FIXTURE_MODE = "batch"
"#,
            fixture.creds.display(),
            auth.display()
        ),
    );
    let second = fixture
        .plan(launch_args("fixture", &fixture.workspace))
        .unwrap()
        .resolved
        .digest;
    assert_eq!(first, second, "order and spelling are not semantics");

    let changed = std::fs::read_to_string(fixture.config.join("launch/fixture.toml"))
        .unwrap()
        .replace("\"batch\"", "\"interactive\"");
    fixture.launch("fixture", &changed);
    let third = fixture
        .plan(launch_args("fixture", &fixture.workspace))
        .unwrap()
        .resolved
        .digest;
    assert_ne!(first, third, "an environment value is semantics");
}

#[test]
fn c01_non_utf8_source_bytes_survive_into_the_snapshot_losslessly() {
    let fixture = Fixture::new();
    fixture.launch(
        "fixture",
        "name = \"fixture\"\njail = \"agent\"\n[credentials.a]\nsource = \"~/cred\"\n\
         dest = \"a\"\nmode = \"copy_rw\"\n",
    );
    // An operator home whose bytes are not UTF-8: resolution never touches
    // the file, so this works on a filesystem that would refuse the name.
    let mut home = fixture.root.clone().into_os_string().into_vec();
    home.extend_from_slice(b"/h\xffme");
    let home = PathBuf::from(std::ffi::OsString::from_vec(home.clone()));
    let ctx = fixture.context(Box::new(Sim::default()), Some(home.clone()));
    let plan = supervisor::resolve_plan(&ctx, &launch_args("fixture", &fixture.workspace))
        .expect("resolves");
    let canonical = plan.resolved.snapshot.to_canonical_value().unwrap();
    let source = &canonical["launch"]["credentials"][0]["source"];
    assert_eq!(source["encoding"], "base64", "{source}");
    let decoded = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(source["data"].as_str().unwrap())
            .unwrap()
    };
    let mut expected = home.into_os_string().into_vec();
    expected.extend_from_slice(b"/cred");
    assert_eq!(decoded, expected);
    assert_schema("policy-snapshot", &canonical);
}

#[test]
fn c01_every_ld_and_dyld_launch_key_refuses_through_the_file() {
    let fixture = Fixture::new();
    for name in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_BIND_NOW",
        "Ld_Debug",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FRAMEWORK_PATH",
        "dyld_fallback_library_path",
    ] {
        for text in [
            format!("name = \"fixture\"\njail = \"tool\"\n[environment]\n{name} = \"/x.so\"\n"),
            format!("name = \"fixture\"\njail = \"tool\"\nstate_var = \"{name}\"\n"),
        ] {
            fixture.launch("fixture", &text);
            let error = refused(
                fixture.plan(launch_args("fixture", &fixture.workspace)),
                &format!("{name} must refuse"),
            );
            assert_eq!(error.code, ErrorCode::InvalidConfig, "{name}");
            assert_eq!(error.exit_code(), 2);
        }
    }
}

#[test]
fn c01_unsafe_state_subdirs_refuse_through_the_file() {
    let fixture = Fixture::new();
    for subdirs in [
        r#"[""]"#,
        r#"["/etc"]"#,
        r#"["../escape"]"#,
        r#"["a/../../b"]"#,
        r#"["."]"#,
        r#"["a", "a"]"#,
        r#"["a//b"]"#,
    ] {
        fixture.launch(
            "fixture",
            &format!("name = \"fixture\"\njail = \"tool\"\nstate_subdirs = {subdirs}\n"),
        );
        let error = refused(
            fixture.plan(launch_args("fixture", &fixture.workspace)),
            subdirs,
        );
        assert_eq!(
            error.key_path.as_deref(),
            Some("launch.state_subdirs"),
            "{subdirs}"
        );
    }
}

#[test]
fn s6_1_tool_and_build_reject_credentials_and_none_rejects_any_launch() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let mut args = launch_args("fixture", &fixture.workspace);
    args.profile = Some("tool".into());
    let error = refused(fixture.plan(args), "tool rejects credentials");
    assert_eq!(error.key_path.as_deref(), Some("launch.credentials"));

    fixture.launch(
        "tooled",
        &format!(
            "name = \"tooled\"\njail = \"tool\"\n[credentials.a]\nsource = \"{}\"\n\
             dest = \"a\"\nmode = \"copy_rw\"\n",
            auth.display()
        ),
    );
    let error = refused(
        fixture.plan(launch_args("tooled", &fixture.workspace)),
        "a tool-jail launch profile rejects credentials",
    );
    assert_eq!(error.key_path.as_deref(), Some("launch.credentials"));

    fixture.launch(
        "plain",
        "name = \"plain\"\njail = \"tool\"\nstate_var = \"PLAIN_HOME\"\n",
    );
    let mut args = launch_args("plain", &fixture.workspace);
    args.profile = Some("none".into());
    let error = refused(fixture.plan(args), "none never runs a launch profile");
    assert_eq!(error.code, ErrorCode::PolicyWidening);
    let plan = fixture
        .plan(launch_args("plain", &fixture.workspace))
        .expect("a credential-free tool launch profile resolves");
    assert_eq!(plan.resolved.snapshot.profile, ProfileName::Tool);
    assert!(
        !plan
            .resolved
            .requirements
            .iter()
            .any(|requirement| requirement == "credential_staging")
    );

    let mut args = launch_args("plain", &fixture.workspace);
    args.profile = Some("agent".into());
    assert_eq!(
        fixture.plan(args).unwrap().resolved.snapshot.profile,
        ProfileName::Agent,
        "an explicit profile that permits the launch profile overrides its default"
    );
}

#[test]
fn a_project_file_can_shrink_the_launch_hosts_but_not_add_credentials() {
    let fixture = Fixture::new();
    fixture.launch(
        "hosts",
        "name = \"hosts\"\njail = \"agent\"\n[network]\nallow = [\"a.example.test:443\", \"b.example.test:443\"]\n",
    );
    std::fs::write(
        fixture.workspace.join("ouro.toml"),
        "[jail.network]\nallow = [\"a.example.test:443\"]\n",
    )
    .unwrap();
    let plan = fixture
        .plan(launch_args("hosts", &fixture.workspace))
        .unwrap();
    assert_eq!(plan.resolved.snapshot.network.allow, ["a.example.test:443"]);

    std::fs::write(
        fixture.workspace.join("ouro.toml"),
        "[jail.credentials.x]\nsource = \"/etc/passwd\"\ndest = \"x\"\nmode = \"copy_rw\"\n",
    )
    .unwrap();
    assert!(
        fixture
            .plan(launch_args("hosts", &fixture.workspace))
            .is_err()
    );
}

#[test]
fn a_launch_file_must_be_private_single_linked_regular_and_outside_writable_grants() {
    let fixture = Fixture::new();
    let text = "name = \"fixture\"\njail = \"tool\"\nstate_var = \"F_HOME\"\n";
    let path = fixture.launch("fixture", text);
    assert!(
        fixture
            .plan(launch_args("fixture", &fixture.workspace))
            .is_ok()
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        fixture
            .plan(launch_args("fixture", &fixture.workspace))
            .is_err(),
        "mode 0644 refuses"
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let alias = fixture.outside.join("alias.toml");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(
        fixture
            .plan(launch_args("fixture", &fixture.workspace))
            .is_err(),
        "a second hard link refuses"
    );
    std::fs::remove_file(&alias).unwrap();

    std::fs::rename(&path, fixture.outside.join("real.toml")).unwrap();
    std::os::unix::fs::symlink(fixture.outside.join("real.toml"), &path).unwrap();
    assert!(
        fixture
            .plan(launch_args("fixture", &fixture.workspace))
            .is_err(),
        "a symlinked launch file refuses"
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(fixture.outside.join("real.toml"), &path).unwrap();

    // The configuration directory inside the workspace: the child could
    // rewrite its own launch authority.
    let mut args = launch_args("fixture", &fixture.root);
    args.workspace = Some(fixture.root.clone());
    let error = refused(fixture.plan(args), "inside the workspace refuses");
    assert_eq!(error.key_path.as_deref(), Some("--launch"));

    // ... and inside an explicit writable grant.
    let mut args = launch_args("fixture", &fixture.workspace);
    args.rw = vec![fixture.config.clone()];
    let error = refused(fixture.plan(args), "inside a --rw grant refuses");
    assert_eq!(error.key_path.as_deref(), Some("--launch"));

    // A launch name is a name, never a path.
    for name in ["../fixture", "Fixture", "fix/ture", ""] {
        assert!(
            fixture.plan(launch_args(name, &fixture.workspace)).is_err(),
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------
// The attempt lifecycle over the simulated platform (C01, C02, P04)
// ---------------------------------------------------------------------------

fn plant_child_activity(vendor: &Path, outside: &Path) {
    // Links out of vendor state, to a file and to a directory, a hard link
    // to an outside file, a FIFO, a socket node, an unreadable subtree and a
    // deep one: everything a child could leave for cleanup to trip over.
    std::os::unix::fs::symlink(outside.join("precious"), vendor.join("file-link")).unwrap();
    std::os::unix::fs::symlink(outside, vendor.join("dir-link")).unwrap();
    std::os::unix::fs::symlink("/", vendor.join("sessions/root-link")).unwrap();
    std::fs::hard_link(outside.join("precious"), vendor.join("hard-link")).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(vendor.join("fifo"))
            .status()
            .unwrap()
            .success()
    );
    socket_node(&vendor.join("sock"));
    let locked = vendor.join("sessions/deep/locked");
    std::fs::create_dir_all(locked.join("inner")).unwrap();
    std::fs::write(locked.join("inner/file"), b"x").unwrap();
    std::fs::set_permissions(locked.join("inner"), std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o100)).unwrap();
    let mut deep = vendor.join("cache");
    for _ in 0..200 {
        deep.push("d");
    }
    std::fs::create_dir_all(&deep).unwrap();
    // The copy is the child's to change; the source never is.
    std::fs::write(vendor.join("auth.json"), b"refreshed-by-the-child").unwrap();
}

/// Leaves a socket node at `path`, which may be longer than `sun_path`:
/// bound under a short directory, then renamed into place.
fn socket_node(path: &Path) {
    let short = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let bound = short.path().join("s");
    drop(std::os::unix::net::UnixListener::bind(&bound).unwrap());
    std::fs::rename(&bound, path).unwrap();
}

fn assert_outside_untouched(fixture: &Fixture) {
    assert_eq!(
        std::fs::read(fixture.outside.join("precious")).unwrap(),
        b"outside the attempt"
    );
    let names: Vec<String> = std::fs::read_dir(&fixture.outside)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        ["precious"],
        "nothing outside was created or removed"
    );
}

#[test]
fn c01_c02_a_normal_exit_stages_both_modes_records_provenance_and_cleans_vendor_state() {
    let fixture = Fixture::new();
    let auth_bytes = b"{\"token\":\"fixture-secret-copy\"}";
    let config_bytes = b"secret = \"fixture-secret-bind\"\n";
    let auth = fixture.credential("auth.json", auth_bytes);
    let config = fixture.credential("config.toml", config_bytes);
    let before = (
        std::fs::metadata(&auth).unwrap(),
        std::fs::metadata(&config).unwrap(),
    );
    agent_profile(&fixture, &auth, &config);

    let outside = fixture.outside.clone();
    let vendor_snapshot: Arc<Mutex<Vec<Listed>>> = Arc::default();
    let listing = Arc::clone(&vendor_snapshot);
    let sim = Sim {
        activity: Some(Arc::new(move |vendor: &Path| {
            // What staging left, before the "child" touches anything.
            let mut rows = Vec::new();
            for relative in ["auth.json", "conf/config.toml"] {
                let path = vendor.join(relative);
                let metadata = std::fs::symlink_metadata(&path).unwrap();
                rows.push((
                    relative.to_owned(),
                    std::fs::read(&path).unwrap(),
                    metadata.mode() & 0o7777,
                ));
            }
            for directory in ["sessions", "sessions/deep", "cache", "conf"] {
                let metadata = std::fs::symlink_metadata(vendor.join(directory)).unwrap();
                rows.push((directory.to_owned(), Vec::new(), metadata.mode() & 0o7777));
            }
            rows.push((
                ".".to_owned(),
                Vec::new(),
                std::fs::symlink_metadata(vendor).unwrap().mode() & 0o7777,
            ));
            *listing.lock().unwrap() = rows;
            plant_child_activity(vendor, &outside);
        })),
        ..Sim::default()
    };
    let seen = Arc::clone(&sim.seen);
    let report = fixture.run(sim, &["--launch", "fixture"]);
    assert_eq!(report.exit_code, 0, "{:?}", report.error);

    // Staging: the copy holds the source bytes at 0600, the bind point is an
    // empty 0600 file, the directories are 0700.
    let rows = vendor_snapshot.lock().unwrap().clone();
    let row = |name: &str| rows.iter().find(|row| row.0 == name).unwrap().clone();
    assert_eq!(row("auth.json").1, auth_bytes);
    assert_eq!(row("auth.json").2, 0o600);
    assert!(
        row("conf/config.toml").1.is_empty(),
        "the bind point is empty"
    );
    for directory in ["sessions", "sessions/deep", "cache", "conf", "."] {
        assert_eq!(row(directory).2, 0o700, "{directory}");
    }
    // The bind handle is the exact source object.
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.binds.len(), 1);
    assert_eq!(seen.binds[0].0, "config");
    assert_eq!(seen.binds[0].1, "conf/config.toml");
    assert_eq!(seen.binds[0].2, (before.1.dev(), before.1.ino()));

    // Provenance without bytes, and a receipt the contract accepts.
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["phase"], "settled");
    assert_eq!(receipt["state_cleanup"], "complete");
    assert_eq!(receipt["cleanup_error"], serde_json::Value::Null);
    let credentials = receipt["credentials"].as_array().unwrap();
    assert_eq!(credentials.len(), 2);
    assert_eq!(credentials[0]["id"], "auth");
    assert_eq!(credentials[0]["mode"], "copy_rw");
    assert_eq!(credentials[0]["digest"], sha256(auth_bytes));
    assert_eq!(
        credentials[0]["digest_unavailable_reason"],
        serde_json::Value::Null
    );
    assert_eq!(credentials[1]["id"], "config");
    assert_eq!(credentials[1]["mode"], "bind_ro");
    assert_eq!(
        credentials[1]["digest"],
        serde_json::Value::Null,
        "a live operator file has no stable content to digest"
    );
    assert_eq!(
        credentials[1]["digest_unavailable_reason"],
        ouro_jail::credentials::REASON_SOURCE_MUTABLE
    );
    let dir = attempt_dir(&report);
    for file in ["jail.json", "trace.ndjson", "jail-state.json"] {
        let text = std::fs::read(dir.join(file)).unwrap_or_default();
        let text = String::from_utf8_lossy(&text);
        for secret in ["fixture-secret-copy", "fixture-secret-bind"] {
            assert!(!text.contains(secret), "{file} carries credential bytes");
        }
        if file != "jail-state.json" {
            assert!(
                !text.contains(&*fixture.creds.to_string_lossy()),
                "{file} carries a credential source path"
            );
        }
    }

    // Sources preserved, byte for byte and in metadata.
    assert_eq!(std::fs::read(&auth).unwrap(), auth_bytes);
    assert_eq!(std::fs::read(&config).unwrap(), config_bytes);
    let after = (
        std::fs::metadata(&auth).unwrap(),
        std::fs::metadata(&config).unwrap(),
    );
    assert_eq!(after.0.mtime(), before.0.mtime());
    assert_eq!(after.1.mtime(), before.1.mtime());
    assert_eq!(after.0.mode(), before.0.mode());

    // Cleanup: vendor state is gone, nothing outside it moved, and jail state
    // agrees with the receipt.
    assert!(cleanup::absent(&dir.join("vendor-state")));
    assert_outside_untouched(&fixture);
    let state = jail_state(&report);
    assert_eq!(state["state_cleanup"], "complete");
    assert_eq!(
        state["vendor_state"]["credentials"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        !serde_json::to_string(&state["vendor_state"])
            .unwrap()
            .contains(&*fixture.creds.to_string_lossy()),
        "private state keeps identities, not paths"
    );
    // The settled receipt was persisted as pending before the removal.
    assert_eq!(
        receipt["revision"], 4,
        "prepared, enforced, settled as pending, then settled as complete"
    );
}

#[test]
fn p04_credential_special_files_and_oversize_refuse_before_the_platform_prepares() {
    let fixture = Fixture::new();
    let good = fixture.credential("good", b"staged before the failure");
    let special = fixture.creds.join("special");
    let cases: Vec<(&str, Maker)> = vec![
        (
            "a FIFO",
            Box::new(|path: &Path| {
                assert!(
                    std::process::Command::new("mkfifo")
                        .arg(path)
                        .status()
                        .unwrap()
                        .success()
                );
            }),
        ),
        (
            "a socket",
            Box::new(|path: &Path| {
                socket_node(path);
            }),
        ),
        (
            "a symlink",
            Box::new(|path: &Path| {
                std::os::unix::fs::symlink("/etc/hosts", path).unwrap();
            }),
        ),
        (
            "a directory",
            Box::new(|path: &Path| {
                std::fs::create_dir(path).unwrap();
                std::fs::write(path.join("inside"), b"x").unwrap();
            }),
        ),
        (
            "bytes",
            Box::new(|path: &Path| {
                let file = std::fs::File::create(path).unwrap();
                file.set_len(ouro_jail::credentials::COPY_BUDGET + 1)
                    .unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }),
        ),
        (
            "mode 0666",
            Box::new(|path: &Path| {
                std::fs::write(path, b"x").unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
            }),
        ),
    ];
    for (label, make) in cases {
        let _ = std::fs::remove_dir_all(&special);
        let _ = std::fs::remove_file(&special);
        make(&special);
        fixture.launch(
            "special",
            &format!(
                "name = \"special\"\njail = \"agent\"\n\
                 [credentials.a-good]\nsource = \"{}\"\ndest = \"good\"\nmode = \"copy_rw\"\n\
                 [credentials.b-special]\nsource = \"{}\"\ndest = \"special\"\nmode = \"copy_rw\"\n",
                good.display(),
                special.display()
            ),
        );
        let sim = Sim::default();
        let seen = Arc::clone(&sim.seen);
        let report = fixture.run(sim, &["--launch", "special"]);
        assert_eq!(report.exit_code, 125, "{label}: {:?}", report.error);
        let error = report.error.as_ref().unwrap();
        assert_eq!(error.code, ErrorCode::CredentialUnavailable, "{label}");
        assert!(
            !seen.lock().unwrap().prepared,
            "{label}: refused before prepare"
        );
        let receipt = receipt_json(&report);
        assert_schema("jail-receipt", &receipt);
        assert_eq!(receipt["phase"], "refused", "{label}");
        assert_eq!(receipt["exec_observed"], false);
        assert_eq!(
            receipt["credentials"].as_array().unwrap().len(),
            1,
            "{label}: the input staged before the failure is reported"
        );
        assert_eq!(receipt["credentials"][0]["id"], "a-good");
        assert_eq!(receipt["state_cleanup"], "complete", "{label}");
        // J3 review RM30: the refused receipt was persisted as `pending`
        // before the removal, so a crash during it leaves a receipt `gc` can
        // finish; the final one is the second revision.
        assert_eq!(receipt["revision"], 2, "{label}");
        assert!(cleanup::absent(&attempt_dir(&report).join("vendor-state")));
        assert!(
            !receipt
                .to_string()
                .contains(&*fixture.creds.to_string_lossy()),
            "{label}: the refusal names the id, not the path"
        );
    }
    // A device node: `/dev/null` is a character device on both platforms.
    fixture.launch(
        "device",
        "name = \"device\"\njail = \"agent\"\n[credentials.dev]\nsource = \"/dev/null\"\n\
         dest = \"dev\"\nmode = \"bind_ro\"\n",
    );
    let sim = Sim::default();
    let seen = Arc::clone(&sim.seen);
    let report = fixture.run(sim, &["--launch", "device"]);
    assert_eq!(report.exit_code, 125);
    assert!(
        report
            .error
            .as_ref()
            .unwrap()
            .message
            .contains("character device"),
        "{:?}",
        report.error
    );
    assert!(!seen.lock().unwrap().prepared);
}

#[test]
fn c02_an_unverified_tree_retains_vendor_state_and_gc_will_not_remove_it() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let report = fixture.run(
        Sim {
            tree: TreeEnd::Unknown,
            ..Sim::default()
        },
        &["--launch", "fixture"],
    );
    assert_eq!(report.error.as_ref().unwrap().code, ErrorCode::TreeUnknown);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_ne!(receipt["phase"], "settled");
    assert_eq!(receipt["state_cleanup"], "pending");
    assert_eq!(receipt["cleanup_error"], cleanup::REASON_TREE_UNVERIFIED);
    let vendor = attempt_dir(&report).join("vendor-state");
    assert!(
        vendor.join("auth.json").exists(),
        "retained for a possibly live tree"
    );
    let gc = fixture.gc(false).expect("gc scans");
    assert_eq!(gc.entries.len(), 1);
    assert_eq!(gc.entries[0].action, "retained");
    assert!(
        gc.entries[0]
            .reason
            .contains(cleanup::REASON_TREE_UNVERIFIED)
    );
    assert!(vendor.join("auth.json").exists());
}

#[test]
fn c02_a_release_failure_after_setup_retains_and_an_exec_error_with_verified_teardown_cleans() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);

    let report = fixture.run(
        Sim {
            release_fails: true,
            ..Sim::default()
        },
        &["--launch", "fixture"],
    );
    assert_eq!(report.exit_code, 125);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(
        receipt["state_cleanup"], "pending",
        "no teardown was verified"
    );
    assert!(attempt_dir(&report).join("vendor-state").exists());

    // The same failure, from a platform that reports a verified teardown.
    let report = fixture.run(
        Sim {
            release_fails: true,
            release_teardown_verified: true,
            ..Sim::default()
        },
        &["--launch", "fixture"],
    );
    assert_eq!(report.exit_code, 125);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["lifetime"]["tree_empty"], true);
    assert_eq!(receipt["state_cleanup"], "complete");
    assert!(cleanup::absent(&attempt_dir(&report).join("vendor-state")));

    let report = fixture.run(
        Sim {
            target: TargetEnd::ExecError,
            ..Sim::default()
        },
        &["--launch", "fixture"],
    );
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["outcome"]["kind"], "exec_error");
    assert_eq!(receipt["lifetime"]["tree_empty"], true);
    assert_eq!(receipt["state_cleanup"], "complete");
    assert!(cleanup::absent(&attempt_dir(&report).join("vendor-state")));
}

/// Leaves one entry vendor-state cleanup cannot remove on its first pass.
///
/// macOS: the user-immutable flag, which the owner may set and clear.
/// Linux: more entries than one pass visits, since an unprivileged owner has
/// no immutable flag there.
fn obstruct_first_pass(vendor: &Path) -> Undo {
    if cfg!(target_os = "macos") {
        let pinned = vendor.join("pinned");
        std::fs::write(&pinned, b"x").unwrap();
        assert!(
            std::process::Command::new("chflags")
                .arg("uchg")
                .arg(&pinned)
                .status()
                .unwrap()
                .success()
        );
        Box::new(move || {
            assert!(
                std::process::Command::new("chflags")
                    .arg("nouchg")
                    .arg(&pinned)
                    .status()
                    .unwrap()
                    .success()
            );
        })
    } else {
        let many = vendor.join("many");
        std::fs::create_dir(&many).unwrap();
        for index in 0..=cleanup::DEFAULT_MAX_ENTRIES {
            std::fs::File::create(many.join(index.to_string())).unwrap();
        }
        Box::new(|| {})
    }
}

#[test]
fn c02_an_interrupted_cleanup_stays_pending_and_gc_resumes_it() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let release: Arc<Mutex<Option<Undo>>> = Arc::default();
    let slot = Arc::clone(&release);
    let sim = Sim {
        activity: Some(Arc::new(move |vendor: &Path| {
            *slot.lock().unwrap() = Some(obstruct_first_pass(vendor));
        })),
        ..Sim::default()
    };
    let report = fixture.run(sim, &["--launch", "fixture"]);
    assert_eq!(
        report.exit_code, 0,
        "cleanup failure never rewrites the exit"
    );
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["phase"], "settled");
    assert_eq!(receipt["state_cleanup"], "pending");
    assert!(receipt["cleanup_error"].is_string());
    assert_eq!(jail_state(&report)["state_cleanup"], "pending");
    let vendor = attempt_dir(&report).join("vendor-state");
    assert!(vendor.exists());

    let dry = fixture.gc(true).expect("a dry run scans");
    assert_eq!(dry.entries[0].action, "would_remove_vendor_state");
    assert!(vendor.exists(), "a dry run removes nothing");

    if let Some(undo) = release.lock().unwrap().take() {
        undo();
    }
    let resumed = fixture.gc(false).expect("the resumed cleanup completes");
    assert_eq!(resumed.entries[0].action, "removed_vendor_state");
    assert!(cleanup::absent(&vendor));
    let after: Receipt =
        serde_json::from_slice(&std::fs::read(attempt_dir(&report).join("jail.json")).unwrap())
            .unwrap();
    assert_eq!(after.state_cleanup, StateCleanup::Complete);
    assert_eq!(after.revision, receipt["revision"].as_u64().unwrap() + 1);
    assert_schema("jail-receipt", &serde_json::to_value(&after).unwrap());
    assert_eq!(jail_state(&report)["state_cleanup"], "complete");
    let again = fixture.gc(false).unwrap();
    assert_eq!(again.entries[0].action, "retained", "nothing left to do");
    assert_outside_untouched(&fixture);
}

#[test]
fn c02_a_crash_after_the_removal_but_before_the_record_is_finished_by_gc() {
    let fixture = Fixture::new();
    fixture.launch(
        "plain",
        "name = \"plain\"\njail = \"tool\"\nstate_subdirs = [\"a/b\"]\n",
    );
    let report = fixture.run(Sim::default(), &["--launch", "plain"]);
    assert_eq!(report.exit_code, 0, "{:?}", report.error);
    let dir = attempt_dir(&report);
    // Rewind both records to the moment between the removal and its record,
    // as a crash there would leave them.
    let mut receipt: Receipt =
        serde_json::from_slice(&std::fs::read(dir.join("jail.json")).unwrap()).unwrap();
    receipt.state_cleanup = StateCleanup::Pending;
    std::fs::write(dir.join("jail.json"), serde_json::to_vec(&receipt).unwrap()).unwrap();
    let mut state = jail_state(&report);
    state["state_cleanup"] = "pending".into();
    std::fs::write(
        dir.join("jail-state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();

    let resumed = fixture.gc(false).unwrap();
    assert_eq!(resumed.entries[0].action, "removed_vendor_state");
    let after: Receipt =
        serde_json::from_slice(&std::fs::read(dir.join("jail.json")).unwrap()).unwrap();
    assert_eq!(after.state_cleanup, StateCleanup::Complete);
    assert_eq!(jail_state(&report)["state_cleanup"], "complete");
}

#[test]
fn c02_a_replaced_vendor_state_directory_is_never_deleted() {
    let fixture = Fixture::new();
    fixture.launch(
        "plain",
        "name = \"plain\"\njail = \"tool\"\nstate_subdirs = [\"a\"]\n",
    );
    let outside = fixture.outside.clone();
    let sim = Sim {
        activity: Some(Arc::new(move |vendor: &Path| {
            // Something with the operator's own rights swaps the registered
            // directory for a link to an outside one.
            let parked = vendor.with_file_name("parked");
            std::fs::rename(vendor, &parked).unwrap();
            std::os::unix::fs::symlink(&outside, vendor).unwrap();
        })),
        ..Sim::default()
    };
    let report = fixture.run(sim, &["--launch", "plain"]);
    assert_eq!(report.exit_code, 0);
    let receipt = receipt_json(&report);
    assert_eq!(receipt["state_cleanup"], "pending");
    assert_eq!(receipt["cleanup_error"], "managed_directory_replaced");
    assert_outside_untouched(&fixture);

    // J3 review RM33: a real replaced directory, not a symlink. The
    // registered one is renamed away and a new directory takes its name;
    // only the recorded identity tells them apart, and neither is removed.
    let sim = Sim {
        activity: Some(Arc::new(|vendor: &Path| {
            let parked = vendor.with_file_name("parked");
            std::fs::rename(vendor, &parked).unwrap();
            std::fs::create_dir(vendor).unwrap();
            std::fs::write(vendor.join("precious"), b"not the registered directory").unwrap();
        })),
        ..Sim::default()
    };
    let report = fixture.run(sim, &["--launch", "plain"]);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["state_cleanup"], "pending");
    assert_eq!(receipt["cleanup_error"], "managed_directory_replaced");
    let attempt = attempt_dir(&report);
    assert!(attempt.join("vendor-state/precious").exists());
    assert!(attempt.join("parked/a").is_dir());
}

#[test]
fn an_agent_launch_profile_resolves_and_then_refuses_exactly_as_agent_does_today() {
    // The real platform for this OS: macOS refuses execution as unsupported,
    // Linux refuses `agent` before any boundary (wave 2 enables it). Either
    // way nothing is staged and no vendor state is created.
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let plain = {
        let mut argv: Vec<String> = vec!["ouro-jail".into(), "run".into()];
        argv.extend([
            "--workspace".into(),
            fixture.workspace.display().to_string(),
        ]);
        argv.extend([
            "--profile".into(),
            "agent".into(),
            "--".into(),
            "true".into(),
        ]);
        let cli::Command::Run(args) = cli::Cli::parse_from(argv).command else {
            unreachable!()
        };
        supervisor::run(
            &fixture.context(ouro_jail::platform::current(), None),
            &args,
        )
    };
    let launched = {
        let mut argv: Vec<String> = vec!["ouro-jail".into(), "run".into()];
        argv.extend([
            "--workspace".into(),
            fixture.workspace.display().to_string(),
        ]);
        argv.extend([
            "--launch".into(),
            "fixture".into(),
            "--".into(),
            "true".into(),
        ]);
        let cli::Command::Run(args) = cli::Cli::parse_from(argv).command else {
            unreachable!()
        };
        supervisor::run(
            &fixture.context(
                ouro_jail::platform::current(),
                Some(fixture.root.join("home")),
            ),
            &args,
        )
    };
    assert_eq!(launched.exit_code, 125);
    assert_eq!(launched.exit_code, plain.exit_code);
    assert_eq!(
        launched.error.as_ref().map(|error| error.code),
        plain.error.as_ref().map(|error| error.code)
    );
    let receipt = receipt_json(&launched);
    assert_eq!(receipt["phase"], "refused");
    assert_eq!(receipt["state_cleanup"], "not_needed");
    assert_eq!(receipt["credentials"], serde_json::json!([]));
    assert!(cleanup::absent(
        &attempt_dir(&launched).join("vendor-state")
    ));
}

// ---------------------------------------------------------------------------
// Staging, directly (the API the platform and wave 2 call)
// ---------------------------------------------------------------------------

fn stage_one_source(fixture: &Fixture, source: &Path) -> Result<(), (JailError, usize)> {
    let vendor_path = fixture.root.join("vendor");
    let _ = std::fs::remove_dir_all(&vendor_path);
    private_dir(&vendor_path);
    let vendor = ouro_jail::state::anchored::Dir::open_trusted(&vendor_path).unwrap();
    let launch = ouro_jail::policy::LaunchSnapshot {
        state_var: None,
        home_is_state: false,
        state_subdirs: Vec::new(),
        credentials: vec![ouro_jail::policy::CredentialDecl {
            id: "only".into(),
            source: ouro_jail::records::NativeString::from_bytes(
                source.as_os_str().as_bytes().to_vec(),
            )
            .unwrap(),
            dest: ouro_jail::records::NativeString::Text("only".into()),
            mode: "copy_rw".into(),
        }],
    };
    ouro_jail::credentials::stage(&launch, vendor.as_fd(), &[])
        .map(|_| ())
        .map_err(|refusal| (refusal.error, refusal.staged.len()))
}

#[test]
fn p04_a_source_reached_through_a_symlinked_directory_refuses() {
    let fixture = Fixture::new();
    let real = fixture.creds.join("real");
    private_dir(&real);
    fixture_file(&real.join("token"), b"t");
    std::os::unix::fs::symlink(&real, fixture.creds.join("alias")).unwrap();
    assert!(stage_one_source(&fixture, &real.join("token")).is_ok());
    let (error, _) = stage_one_source(&fixture, &fixture.creds.join("alias/token"))
        .expect_err("a symlinked component is never followed");
    assert_eq!(error.code, ErrorCode::CredentialUnavailable);
    assert!(error.message.contains("a symlink"), "{}", error.message);
}

#[test]
fn p04_a_source_below_a_directory_others_can_write_refuses() {
    let fixture = Fixture::new();
    let shared = fixture.creds.join("shared");
    private_dir(&shared);
    fixture_file(&shared.join("token"), b"t");
    assert!(stage_one_source(&fixture, &shared.join("token")).is_ok());
    // World-writable: "others" on every host. (A group-writable parent is
    // others only when the group is not the owner's private group, which
    // depends on the host's accounts; state.rs tests that rule.)
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (error, _) = stage_one_source(&fixture, &shared.join("token"))
        .expect_err("a parent anyone can write lets someone else swap the source");
    assert!(
        error.message.contains("writable by others"),
        "{}",
        error.message
    );
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1770)).unwrap();
    assert!(
        stage_one_source(&fixture, &shared.join("token")).is_ok(),
        "a sticky shared directory protects entries its owner made"
    );
}

/// A source whose bytes do not match the size `fstat` reported is changing
/// under the copy; `/proc/<pid>/status` is such a file, owned by this user.
#[cfg(target_os = "linux")]
#[test]
fn c01_a_source_that_changes_under_the_copy_refuses_rather_than_tearing() {
    let fixture = Fixture::new();
    let status = PathBuf::from(format!("/proc/{}/status", std::process::id()));
    let (error, _) = stage_one_source(&fixture, &status)
        .expect_err("a source whose content disagrees with its size refuses");
    assert_eq!(error.code, ErrorCode::CredentialUnavailable);
    assert_eq!(error.remediation, Remediation::Retry);
    assert!(error.message.contains("changed while"), "{}", error.message);
}

// ---------------------------------------------------------------------------
// Inspection output: `explain` and `doctor --launch` (§12, §14.1)
// ---------------------------------------------------------------------------

/// A launch profile with one good, one missing and one special source, all
/// beneath the fixture's own directories, whose paths must never be printed.
fn inspection_fixture() -> Fixture {
    let fixture = Fixture::new();
    let good = fixture.credential("good.json", b"fixture-secret-inspect");
    let fifo = fixture.creds.join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    fixture.launch(
        "inspect",
        &format!(
            "name = \"inspect\"\njail = \"agent\"\nstate_var = \"I_HOME\"\n\
             [credentials.good]\nsource = \"{}\"\ndest = \"good.json\"\nmode = \"copy_rw\"\n\
             [credentials.missing]\nsource = \"{}\"\ndest = \"missing.json\"\nmode = \"copy_rw\"\n\
             [credentials.pipe]\nsource = \"{}\"\ndest = \"conf/pipe\"\nmode = \"bind_ro\"\n",
            good.display(),
            fixture.creds.join("absent.json").display(),
            fifo.display()
        ),
    );
    fixture
}

fn jail_binary(fixture: &Fixture, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_ouro-jail"))
        .args(args)
        .current_dir(&fixture.workspace)
        .env("OURO_CONFIG_DIR", &fixture.config)
        .env("OURO_DATA_DIR", &fixture.data)
        .env("HOME", fixture.root.join("home"))
        .output()
        .unwrap()
}

fn assert_no_private_path(fixture: &Fixture, label: &str, text: &str) {
    for private in [
        fixture.creds.to_string_lossy().into_owned(),
        fixture.root.join("home").to_string_lossy().into_owned(),
        "fixture-secret-inspect".to_owned(),
    ] {
        assert!(
            !text.contains(&private),
            "{label} prints {private}:\n{text}"
        );
    }
}

#[test]
fn explain_prints_credentials_by_id_mode_and_dest_never_by_source() {
    let fixture = inspection_fixture();
    let json = jail_binary(&fixture, &["explain", "--launch", "inspect", "--json"]);
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let stdout = String::from_utf8_lossy(&json.stdout).into_owned();
    assert_no_private_path(&fixture, "explain --json", &stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["policy"]["credential_sources"], "omitted");
    let credentials = value["policy"]["snapshot"]["launch"]["credentials"]
        .as_array()
        .unwrap();
    assert_eq!(credentials.len(), 3);
    for credential in credentials {
        let keys: Vec<&str> = credential
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["dest", "id", "mode"], "{credential}");
    }
    // J4-D7: the snapshot's arrays are in canonical-byte order, and a
    // credential's canonical bytes begin with its `dest` (canonicalization.md),
    // so `conf/pipe` (id `pipe`) comes first, not last as it would by id.
    let dests: Vec<&str> = credentials
        .iter()
        .map(|credential| credential["dest"].as_str().unwrap())
        .collect();
    assert_eq!(dests, ["conf/pipe", "good.json", "missing.json"]);

    let text = jail_binary(&fixture, &["explain", "--launch", "inspect"]);
    assert!(text.status.success());
    let stdout = String::from_utf8_lossy(&text.stdout).into_owned();
    assert_no_private_path(&fixture, "explain", &stdout);
    assert!(
        stdout.contains("launch credential good mode=copy_rw dest=good.json source=omitted"),
        "{stdout}"
    );
}

#[test]
fn doctor_launch_checks_each_credential_without_printing_paths_or_values() {
    let fixture = inspection_fixture();
    let json = jail_binary(&fixture, &["doctor", "--launch", "inspect", "--json"]);
    // Not ready: two sources refuse (and macOS refuses execution too).
    assert_eq!(
        json.status.code(),
        Some(125),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let stdout = String::from_utf8_lossy(&json.stdout).into_owned();
    assert_no_private_path(&fixture, "doctor --json", &stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["ready"], false);
    let launch = &value["launch"];
    assert_eq!(launch["name"], "inspect");
    assert_eq!(launch["support"], "experimental");
    assert_eq!(launch["support_reason"], "no_recorded_run");
    let rows: Vec<(String, String, String)> = launch["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["id"].as_str().unwrap().to_owned(),
                row["status"].as_str().unwrap().to_owned(),
                row["reason_code"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("good".into(), "available".into(), "ok".into()),
            (
                "missing".into(),
                "unavailable".into(),
                "source_missing".into()
            ),
            (
                "pipe".into(),
                "unavailable".into(),
                "source_not_regular_file".into()
            ),
        ]
    );

    let text = jail_binary(&fixture, &["doctor", "--launch", "inspect"]);
    let stdout = String::from_utf8_lossy(&text.stdout).into_owned();
    assert_no_private_path(&fixture, "doctor", &stdout);
    assert!(
        stdout.contains("launch inspect experimental reason=no_recorded_run"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "credential missing mode=copy_rw dest=missing.json unavailable reason=source_missing"
        ),
        "{stdout}"
    );
}

#[test]
fn doctor_readiness_needs_every_credential_and_reports_support_apart_from_it() {
    // The scripted platform satisfies every requirement, so readiness here is
    // decided by the credentials alone.
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let ctx = fixture.context(Box::new(Sim::default()), Some(fixture.root.join("home")));
    let args = cli::DoctorArgs {
        profile: None,
        launch: Some("fixture".into()),
        json: true,
    };
    let report = supervisor::doctor(&ctx, &args).unwrap();
    assert!(report.ready);
    let launch = report.launch.as_ref().unwrap();
    assert_eq!(
        launch.support, "experimental",
        "support is reported whatever readiness says"
    );
    assert!(launch.credentials.iter().all(|check| check.available));

    std::fs::remove_file(&config).unwrap();
    let report = supervisor::doctor(&ctx, &args).unwrap();
    assert!(
        !report.ready,
        "a missing source makes the launch unavailable"
    );
    assert_eq!(report.launch.as_ref().unwrap().support, "experimental");

    // Oversize copies are caught before exec by the same budget.
    let big = std::fs::File::create(&config).unwrap();
    big.set_len(ouro_jail::credentials::COPY_BUDGET).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    fixture.launch(
        "fixture",
        &format!(
            "name = \"fixture\"\njail = \"agent\"\n\
             [credentials.a]\nsource = \"{}\"\ndest = \"a\"\nmode = \"copy_rw\"\n\
             [credentials.b]\nsource = \"{}\"\ndest = \"b\"\nmode = \"copy_rw\"\n",
            auth.display(),
            config.display()
        ),
    );
    let report = supervisor::doctor(&ctx, &args).unwrap();
    let checks = &report.launch.as_ref().unwrap().credentials;
    assert_eq!(checks[0].reason_code, "ok");
    assert_eq!(checks[1].reason_code, "copy_budget_exceeded");
    assert!(!report.ready);
}

// ---------------------------------------------------------------------------
// J3 review findings, adopted as tests
// ---------------------------------------------------------------------------

#[test]
fn h2_a_preexisting_vendor_state_in_a_managed_attempt_root_refuses_and_survives() {
    // Reviewer's R2: a managed caller's attempt root already holding
    // `vendor-state/` was accepted, the create failed, and the refusal then
    // deleted the directory the attempt never made.
    let fixture = Fixture::new();
    fixture.launch(
        "fixture",
        "name = \"fixture\"\njail = \"tool\"\nstate_var = \"FIX_HOME\"\n",
    );
    for artifact in ouro_jail::state::JAIL_OWNED_NAMES {
        let id = format!("att_{}", uuid::Uuid::new_v4());
        private_dir(&fixture.data.join("attempts"));
        let attempt = fixture.data.join("attempts").join(&id);
        private_dir(&attempt);
        let planted = attempt.join(artifact);
        if artifact.contains('.') {
            std::fs::write(&planted, b"not this attempt's").unwrap();
        } else {
            private_dir(&planted);
            std::fs::write(planted.join("precious"), b"not this attempt's").unwrap();
        }
        let (read, write) = std::io::pipe().unwrap();
        let read: std::os::fd::OwnedFd = read.into();
        let gate = std::os::fd::AsRawFd::as_raw_fd(&read).to_string();
        let report = fixture.run(
            Sim::default(),
            &[
                "--launch",
                "fixture",
                "--attempt-id",
                &id,
                "--gate-fd",
                &gate,
            ],
        );
        drop(write);
        let error = report.error.as_ref().expect("a refusal");
        assert_eq!(
            error.code,
            ErrorCode::AttemptExists,
            "{artifact}: {error:?}"
        );
        assert!(
            error.message.contains(artifact),
            "{artifact}: {}",
            error.message
        );
        if artifact.contains('.') {
            assert_eq!(std::fs::read(&planted).unwrap(), b"not this attempt's");
        } else {
            assert!(planted.join("precious").exists(), "{artifact} was touched");
        }
    }
}

#[test]
fn h2_a_vendor_state_appearing_after_the_claim_is_withdrawn_not_deleted() {
    let fixture = Fixture::new();
    fixture.launch(
        "fixture",
        "name = \"fixture\"\njail = \"tool\"\nstate_var = \"FIX_HOME\"\n",
    );
    let sim = Sim {
        plant_vendor_state: Some(fixture.data.clone()),
        ..Sim::default()
    };
    let seen = Arc::clone(&sim.seen);
    let report = fixture.run(sim, &["--launch", "fixture"]);
    assert_eq!(report.exit_code, 125, "{:?}", report.error);
    assert!(!seen.lock().unwrap().prepared);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["phase"], "refused");
    assert_eq!(
        receipt["state_cleanup"], "not_needed",
        "not this attempt's to clean"
    );
    let attempt = attempt_dir(&report);
    assert_eq!(
        std::fs::read(attempt.join("vendor-state/precious")).unwrap(),
        b"not this attempt's"
    );
    let state = jail_state(&report);
    assert_eq!(state["vendor_state"], serde_json::Value::Null);
    // And gc will not touch it either.
    let gc = fixture.gc(false).unwrap();
    assert!(gc.incomplete.is_empty());
    assert!(attempt.join("vendor-state/precious").exists());
}

#[test]
fn m2_a_credential_source_inside_a_child_writable_grant_refuses() {
    // Reviewer's R5: sources inside the workspace were staged, so the child
    // could change the operator's credential through the workspace.
    let fixture = Fixture::new();
    let inside = fixture.workspace.join("config.toml");
    std::fs::write(&inside, b"fixture-config").unwrap();
    std::fs::set_permissions(&inside, std::fs::Permissions::from_mode(0o600)).unwrap();
    for mode in ["bind_ro", "copy_rw"] {
        fixture.launch(
            "fixture",
            &format!(
                "name = \"fixture\"\njail = \"agent\"\n[credentials.c]\nsource = \"{}\"\n\
                 dest = \"c\"\nmode = \"{mode}\"\n",
                inside.display()
            ),
        );
        let sim = Sim::default();
        let seen = Arc::clone(&sim.seen);
        let report = fixture.run(sim, &["--launch", "fixture"]);
        let error = report.error.as_ref().expect("a refusal");
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{mode}");
        assert_eq!(
            error.key_path.as_deref(),
            Some("launch.credentials.c.source")
        );
        assert!(
            report.receipt.is_none(),
            "refused before any attempt existed"
        );
        assert!(!seen.lock().unwrap().prepared);
    }
    // A writable host grant counts as much as the workspace does.
    let source = fixture.credential("token", b"t");
    fixture.launch(
        "fixture",
        &format!(
            "name = \"fixture\"\njail = \"agent\"\n[credentials.t]\nsource = \"{}\"\n\
             dest = \"t\"\nmode = \"copy_rw\"\n",
            source.display()
        ),
    );
    let creds = fixture.creds.display().to_string();
    let report = fixture.run(Sim::default(), &["--launch", "fixture", "--rw", &creds]);
    assert_eq!(
        report
            .error
            .as_ref()
            .and_then(|error| error.key_path.as_deref()),
        Some("launch.credentials.t.source")
    );
    // Staging repeats the comparison on its own walk, by identity.
    use std::os::unix::fs::MetadataExt as _;
    let grant = std::fs::metadata(&fixture.creds).unwrap();
    let (error, staged) = stage_one_source_with(&fixture, &source, &[(grant.dev(), grant.ino())])
        .expect_err("a grant on the walk refuses");
    assert!(
        error.message.contains("grant the child can write"),
        "{}",
        error.message
    );
    assert_eq!(staged, 0);
}

#[test]
fn m2_a_bind_ro_source_with_another_link_refuses_and_a_copy_does_not() {
    let fixture = Fixture::new();
    let source = fixture.credential("token", b"fixture-token");
    std::fs::hard_link(&source, fixture.outside.join("alias")).unwrap();
    for (mode, refused) in [("bind_ro", true), ("copy_rw", false)] {
        fixture.launch(
            "fixture",
            &format!(
                "name = \"fixture\"\njail = \"agent\"\n[credentials.t]\nsource = \"{}\"\n\
                 dest = \"t\"\nmode = \"{mode}\"\n",
                source.display()
            ),
        );
        let report = fixture.run(Sim::default(), &["--launch", "fixture"]);
        if refused {
            let error = report.error.as_ref().expect("a refusal");
            assert_eq!(error.code, ErrorCode::CredentialUnavailable);
            assert!(
                error.message.contains("exactly one link"),
                "{}",
                error.message
            );
        } else {
            assert_eq!(report.exit_code, 0, "{:?}", report.error);
        }
    }
}

#[test]
fn m3_a_configured_profile_is_kept_or_the_conflict_refuses_never_replaced() {
    // Reviewer's R7: `--launch` silently replaced the operator's configured
    // profile and dropped its required ceilings.
    let fixture = Fixture::new();
    std::fs::write(
        fixture.config.join("strict.toml"),
        "schema = \"ouro.jail.policy/1\"\nextends = \"tool\"\n[limits]\npids = 16\nwall = \"1m\"\n",
    )
    .unwrap();
    let configure = |profile: &str| {
        std::fs::write(
            fixture.config.join("config.toml"),
            format!("[jail]\nschema = \"ouro.jail.policy/1\"\nprofile = \"{profile}\"\n"),
        )
        .unwrap();
    };
    configure("strict.toml");
    fixture.launch(
        "tooled",
        "name = \"tooled\"\njail = \"tool\"\nstate_var = \"FIX_HOME\"\n",
    );
    fixture.launch(
        "agented",
        "name = \"agented\"\njail = \"agent\"\nstate_var = \"FIX_HOME\"\n",
    );
    let limits =
        |plan: &supervisor::Plan| serde_json::to_value(&plan.resolved.snapshot.limits).unwrap();
    let without = fixture
        .plan(PolicyArgs {
            workspace: Some(fixture.workspace.clone()),
            ..PolicyArgs::default()
        })
        .unwrap_or_else(|error| panic!("{error:?}"));
    let with = fixture
        .plan(launch_args("tooled", &fixture.workspace))
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(
        limits(&with),
        limits(&without),
        "the configured profile's ceilings stay"
    );
    assert_eq!(
        with.resolved.snapshot.limits.pids.as_ref().unwrap().value,
        "16"
    );

    // Different bases: refuse, naming both and pointing at --profile.
    let error = refused(
        fixture.plan(launch_args("agented", &fixture.workspace)),
        "conflict",
    );
    assert_eq!(error.code, ErrorCode::InvalidConfig);
    assert_eq!(error.key_path.as_deref(), Some("jail.profile"));
    assert!(error.message.contains("strict.toml") && error.message.contains("`agent`"));
    assert!(error.message.contains("--profile"));
    configure("tool");
    let error = refused(
        fixture.plan(launch_args("agented", &fixture.workspace)),
        "conflict",
    );
    assert_eq!(error.key_path.as_deref(), Some("jail.profile"));

    // `--profile` decides; with no configured profile the launch default does.
    let mut args = launch_args("agented", &fixture.workspace);
    args.profile = Some("agent".into());
    assert_eq!(
        fixture.plan(args).unwrap().resolved.snapshot.profile,
        ProfileName::Agent
    );
    std::fs::remove_file(fixture.config.join("config.toml")).unwrap();
    assert_eq!(
        fixture
            .plan(launch_args("agented", &fixture.workspace))
            .unwrap()
            .resolved
            .snapshot
            .profile,
        ProfileName::Agent
    );
}

#[test]
fn l3_credentials_staged_before_a_refusal_reach_private_provenance_too() {
    // Reviewer's R8.
    let fixture = Fixture::new();
    let a = fixture.credential("a", b"fixture-a");
    fixture.launch(
        "fixture",
        &format!(
            "name = \"fixture\"\njail = \"agent\"\n\
             [credentials.a]\nsource = \"{}\"\ndest = \"a\"\nmode = \"copy_rw\"\n\
             [credentials.b]\nsource = \"{}\"\ndest = \"b\"\nmode = \"copy_rw\"\n",
            a.display(),
            fixture.creds.join("missing").display()
        ),
    );
    let report = fixture.run(Sim::default(), &["--launch", "fixture"]);
    assert_eq!(report.exit_code, 125);
    let receipt = receipt_json(&report);
    let state = jail_state(&report);
    let private = state["vendor_state"]["credentials"].as_array().cloned();
    // Cleanup withdrew nothing: the registration keeps its history.
    let private = private.unwrap_or_default();
    assert_eq!(receipt["credentials"].as_array().unwrap().len(), 1);
    assert_eq!(private.len(), 1, "{state:#}");
    assert_eq!(private[0]["id"], "a");
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(
        private[0]["source_ino"],
        std::fs::metadata(&a).unwrap().ino().to_string()
    );
}

#[test]
fn rm16_the_copy_budget_is_cumulative_across_credentials() {
    // Reviewer's R10: two 10 MiB copies must refuse on the second.
    let fixture = Fixture::new();
    let decl = |id: &str| {
        let path = fixture.creds.join(id);
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(10 * 1024 * 1024).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        ouro_jail::policy::CredentialDecl {
            id: id.into(),
            source: ouro_jail::records::NativeString::from_bytes(
                path.as_os_str().as_bytes().to_vec(),
            )
            .unwrap(),
            dest: ouro_jail::records::NativeString::Text(id.into()),
            mode: "copy_rw".into(),
        }
    };
    let launch = ouro_jail::policy::LaunchSnapshot {
        state_var: None,
        home_is_state: false,
        state_subdirs: Vec::new(),
        credentials: vec![decl("one"), decl("two")],
    };
    let vendor_path = fixture.root.join("vendor");
    private_dir(&vendor_path);
    let vendor = ouro_jail::state::anchored::Dir::open_trusted(&vendor_path).unwrap();
    let refusal = ouro_jail::credentials::stage(&launch, vendor.as_fd(), &[])
        .expect_err("20 MiB under a 16 MiB per-attempt budget");
    assert_eq!(refusal.staged.len(), 1);
    assert!(
        refusal.error.message.contains("already copied"),
        "{}",
        refusal.error.message
    );
    assert_eq!(
        ouro_jail::credentials::inspect(&launch, &[])
            .iter()
            .map(|check| check.reason_code)
            .collect::<Vec<_>>(),
        ["ok", "copy_budget_exceeded"]
    );
}

#[test]
fn m4_names_values_and_ids_outside_their_grammars_refuse_through_the_file() {
    // Reviewer's RM50/RM18: the grammar is what keeps a NUL (and so extra
    // bubblewrap options in the `--args` payload) out of the environment.
    let fixture = Fixture::new();
    for (label, text) in [
        (
            "NUL in a name",
            "[environment]\n\"X\\u0000--ro-bind\\u0000/\\u0000/run/leak\" = \"v\"\n".to_owned(),
        ),
        ("= in a name", "[environment]\n\"A=B\" = \"v\"\n".to_owned()),
        (
            "leading digit",
            "[environment]\n\"1A\" = \"v\"\n".to_owned(),
        ),
        ("dash", "[environment]\n\"A-B\" = \"v\"\n".to_owned()),
        ("empty name", "[environment]\n\"\" = \"v\"\n".to_owned()),
        (
            "NUL in a value",
            "[environment]\nFIX = \"x\\u0000--ro-bind\\u0000/\\u0000/run/leak\"\n".to_owned(),
        ),
        ("NUL in state_var", "state_var = \"A\\u0000B\"\n".to_owned()),
        (
            "credential id with a slash",
            "[credentials.\"../x\"]\nsource = \"/c\"\ndest = \"x\"\nmode = \"copy_rw\"\n"
                .to_owned(),
        ),
        (
            "credential id with a space",
            "[credentials.\"a b\"]\nsource = \"/c\"\ndest = \"x\"\nmode = \"copy_rw\"\n".to_owned(),
        ),
        (
            "hidden credential id",
            "[credentials.\".hidden\"]\nsource = \"/c\"\ndest = \"x\"\nmode = \"copy_rw\"\n"
                .to_owned(),
        ),
        (
            "NUL in a destination",
            "[credentials.a]\nsource = \"/c\"\ndest = \"x\\u0000y\"\nmode = \"copy_rw\"\n"
                .to_owned(),
        ),
    ] {
        fixture.launch(
            "fixture",
            &format!("name = \"fixture\"\njail = \"agent\"\n{text}"),
        );
        let error = refused(
            fixture.plan(launch_args("fixture", &fixture.workspace)),
            label,
        );
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{label}: {error:?}");
    }
}

#[test]
fn rm24_rm25_an_oversized_launch_file_or_a_shared_launch_directory_refuses() {
    let fixture = Fixture::new();
    let padding = format!("# {}\n", "x".repeat(70 * 1024));
    fixture.launch(
        "fixture",
        &format!("{padding}name = \"fixture\"\njail = \"tool\"\n"),
    );
    let error = refused(
        fixture.plan(launch_args("fixture", &fixture.workspace)),
        "oversized",
    );
    assert!(error.message.contains("maximum"), "{}", error.message);

    fixture.launch("fixture", "name = \"fixture\"\njail = \"tool\"\n");
    assert!(
        fixture
            .plan(launch_args("fixture", &fixture.workspace))
            .is_ok()
    );
    let launch_dir = fixture.config.join("launch");
    // World-writable, so it is "others" whatever the host's groups are.
    std::fs::set_permissions(&launch_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let error = refused(
        fixture.plan(launch_args("fixture", &fixture.workspace)),
        "shared",
    );
    assert!(
        error.message.contains("writable by others"),
        "{}",
        error.message
    );
    std::fs::set_permissions(&launch_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn rm11_a_teardown_that_lost_integrity_retains_vendor_state_and_says_why() {
    let fixture = Fixture::new();
    fixture.launch(
        "plain",
        "name = \"plain\"\njail = \"tool\"\nstate_subdirs = [\"a\"]\n",
    );
    let report = fixture.run(
        Sim {
            release_fails: true,
            release_teardown_lost: true,
            ..Sim::default()
        },
        &["--launch", "plain"],
    );
    assert_eq!(report.exit_code, 125);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["lifetime"]["integrity"], "lost");
    assert_eq!(receipt["state_cleanup"], "pending");
    assert_eq!(receipt["cleanup_error"], cleanup::REASON_INTEGRITY_LOST);
    assert!(attempt_dir(&report).join("vendor-state/a").is_dir());
}

#[test]
fn l1_gc_prints_its_report_even_when_a_cleanup_stays_pending() {
    // Reviewer's live_gc_json: `gc --json` printed nothing when it exited 1.
    let fixture = Fixture::new();
    fixture.launch(
        "plain",
        "name = \"plain\"\njail = \"tool\"\nstate_subdirs = [\"a\"]\n",
    );
    let sim = Sim {
        activity: Some(Arc::new(|vendor: &Path| {
            let parked = vendor.with_file_name("parked");
            std::fs::rename(vendor, &parked).unwrap();
            std::fs::create_dir(vendor).unwrap();
        })),
        ..Sim::default()
    };
    let report = fixture.run(sim, &["--launch", "plain"]);
    assert_eq!(receipt_json(&report)["state_cleanup"], "pending");
    let output = jail_binary(&fixture, &["gc", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("gc printed no JSON report: {error}"));
    assert_eq!(value["entries"][0]["action"], "pending", "{value}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("did not complete"));
    let text = jail_binary(&fixture, &["gc"]);
    assert_eq!(text.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&text.stdout).contains(" pending "));
}

#[test]
fn a_run_that_created_no_managed_scratch_reports_cleanup_not_needed() {
    // Integration finding: settlement said `complete` for a `none` run whose
    // platform created no managed scratch; nothing created is `not_needed`.
    let fixture = Fixture::new();
    let report = fixture.run(
        Sim {
            unapplied: true,
            ..Sim::default()
        },
        &["--profile", "none"],
    );
    assert_eq!(report.exit_code, 0, "{:?}", report.error);
    let receipt = receipt_json(&report);
    assert_eq!(receipt["phase"], "settled");
    assert_eq!(receipt["state_cleanup"], "not_needed");
}

fn stage_one_source_with(
    fixture: &Fixture,
    source: &Path,
    forbidden: &[(u64, u64)],
) -> Result<(), (JailError, usize)> {
    let vendor_path = fixture.root.join("vendor");
    let _ = std::fs::remove_dir_all(&vendor_path);
    private_dir(&vendor_path);
    let vendor = ouro_jail::state::anchored::Dir::open_trusted(&vendor_path).unwrap();
    let launch = ouro_jail::policy::LaunchSnapshot {
        state_var: None,
        home_is_state: false,
        state_subdirs: Vec::new(),
        credentials: vec![ouro_jail::policy::CredentialDecl {
            id: "only".into(),
            source: ouro_jail::records::NativeString::from_bytes(
                source.as_os_str().as_bytes().to_vec(),
            )
            .unwrap(),
            dest: ouro_jail::records::NativeString::Text("only".into()),
            mode: "copy_rw".into(),
        }],
    };
    ouro_jail::credentials::stage(&launch, vendor.as_fd(), forbidden)
        .map(|_| ())
        .map_err(|refusal| (refusal.error, refusal.staged.len()))
}
