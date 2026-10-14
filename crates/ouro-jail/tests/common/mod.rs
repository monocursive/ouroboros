//! Shared test support.
//!
//! Not a test target: Cargo builds only the top-level `.rs` files in `tests/`,
//! so this is compiled into each binary that declares `mod common;`.

// Each binary uses the part of this module it needs; the rest is not dead so
// much as unused by that particular binary.
#![allow(dead_code)]

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt as _;

use tempfile::TempDir;

/// Simulated platforms for the in-process supervisor tests.
pub mod sim;

/// The bare-tracer scaffolding the observer suites share: the C fixtures
/// under `tests/fixtures/`, built once per binary, and the launcher the
/// tracer seizes.
#[cfg(target_os = "linux")]
pub mod observer;

/// A temporary directory created mode 0700, whatever the umask is.
///
/// `tempfile::tempdir()` creates with 0777 masked by the process umask, so the
/// result is 0755 on a host whose umask is 022 and 0775 on one whose umask is
/// 002. A state root under a group-writable ancestor is refused by
/// `state::check_state_ancestors`, and rightly: §6.2 rejects "unsafe parent
/// replacement", and anyone in that group can swap the next component for
/// their own. The check stays strict; the tests stop handing it a directory
/// that fails it for reasons that have nothing to do with what they test.
///
/// Use it for every temporary directory a test makes, not only for one that
/// builds a state root: which directory ends up a state-root ancestor is a
/// detail that changes when a test is edited, and the umask of the machine
/// running it is not something a test should depend on either way.
pub fn private_tempdir() -> TempDir {
    tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .expect("a temporary directory")
}

// ---------------------------------------------------------------------------
// The descriptor limit a run starts from
// ---------------------------------------------------------------------------

/// This process's `RLIMIT_NOFILE` with its soft limit lowered, which the
/// jail a test spawns inherits; the old limit is put back on drop.
pub struct SoftNofile(libc::rlimit);

impl SoftNofile {
    /// This process's `RLIMIT_NOFILE`.
    #[must_use]
    pub fn read() -> libc::rlimit {
        // SAFETY: an all-zero rlimit is a valid value the call overwrites.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `limit` is writable storage of the type getrlimit fills.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) };
        assert_eq!(rc, 0);
        limit
    }

    /// Lowers the soft limit to `soft` (never above the hard limit).
    #[must_use]
    pub fn set(soft: libc::rlim_t) -> SoftNofile {
        let old = SoftNofile::read();
        let lowered = libc::rlimit {
            rlim_cur: soft.min(old.rlim_max),
            rlim_max: old.rlim_max,
        };
        // SAFETY: a valid rlimit that outlives the call; lowering the soft
        // limit within the hard one needs no privilege.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lowered) };
        assert_eq!(rc, 0);
        SoftNofile(old)
    }
}

impl Drop for SoftNofile {
    fn drop(&mut self) {
        // SAFETY: restores the limit read at construction, within the
        // unchanged hard limit.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const self.0) };
    }
}

// ---------------------------------------------------------------------------
// Bounded waits
// ---------------------------------------------------------------------------

/// How often a bounded wait looks again.
pub const POLL: std::time::Duration = std::time::Duration::from_millis(5);

/// How long a live run may take to reach a state a test waits for (a
/// receipt phase, a cgroup emptying, a helper's ready file). Generous on
/// purpose: it only turns a hang into a failure under load, it never orders
/// two events.
pub const SETTLE_BOUND: std::time::Duration = std::time::Duration::from_secs(20);

/// How long one step of a live run may take: a launcher appearing or
/// blocking, a marker written, a process ending. Like [`SETTLE_BOUND`], a
/// bound against a hang, never a way to order two events.
pub const STEP_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a tree or a cgroup takes to be gone once it was killed
/// (`SIGKILL`, `cgroup.kill`) or let go: the kernel acts at once, so this
/// only absorbs scheduling under load.
pub const KILL_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// Wait until `ready` holds, looking every [`POLL`]; fail the test naming
/// `what` when `bound` passes first.
pub fn eventually(what: &str, bound: std::time::Duration, ready: impl FnMut() -> bool) {
    assert!(
        within(bound, ready),
        "timed out after {bound:?} waiting for {what}"
    );
}

/// [`eventually`] for a probe that finds something: wait until `probe`
/// returns it, looking every [`POLL`], and hand it back; fail the test naming
/// `what` when `bound` passes first.
pub fn eventually_some<T>(
    what: &str,
    bound: std::time::Duration,
    mut probe: impl FnMut() -> Option<T>,
) -> T {
    let mut found = None;
    eventually(what, bound, || {
        found = probe();
        found.is_some()
    });
    found.expect("the wait ended on a probe that found it")
}

/// Whether `ready` came to hold within `bound`, looking every [`POLL`]: for a
/// caller that reports the timeout itself (a cleanup in `Drop`, a crash
/// matrix that collects problems) rather than failing on the spot.
#[must_use]
pub fn within(bound: std::time::Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + bound;
    loop {
        if ready() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

// ---------------------------------------------------------------------------
// Self-exec helpers
// ---------------------------------------------------------------------------

/// The variable a parent test sets to the name of the helper it runs.
pub const HELPER_VAR: &str = "OURO_TEST_HELPER";

/// What a helper prints, followed by its name, once its guard let it run
/// ([`running_helper`]); [`assert_helper_ran`] requires the line.
pub const HELPER_RAN: &str = "ouro-test-helper-ran:";

/// Whether this process is running helper `name` for a parent test.
///
/// A self-exec helper is an `#[ignore]`d test of its own binary that a parent
/// test runs in a child process. `--include-ignored` runs it too, with no
/// parent and none of its inputs, so every helper calls this first and
/// returns when it is false: it then does nothing, rather than panicking or
/// acting on a host it was not set up for.
///
/// That early return still passes, so a helper whose guard variable was lost
/// on the way (an environment the jail scrubbed, a renamed variable) reports
/// "1 passed" without running its body. When the guard lets it run, this
/// prints [`HELPER_RAN`] and the helper's name on a line of its own, and a
/// parent's [`assert_helper_ran`] requires that line.
#[must_use]
pub fn running_helper(name: &str) -> bool {
    let running = std::env::var_os(HELPER_VAR).is_some_and(|value| value == name);
    if running {
        println!("{HELPER_RAN} {name}");
    }
    running
}

/// The arguments that run exactly the `#[ignore]`d test `name` of a test
/// binary, uncaptured. (One test runs on one thread either way; with
/// `--test-threads=1` libtest would print the test's name on the line its
/// output starts on, and a helper's report lines would no longer start the
/// line.)
#[must_use]
pub fn helper_args(name: &str) -> [&str; 4] {
    ["--ignored", "--exact", name, "--nocapture"]
}

/// The command that runs helper `name` of this test binary in a child
/// process, with [`HELPER_VAR`] naming it ([`running_helper`]).
#[must_use]
pub fn helper_command(name: &str) -> std::process::Command {
    let mut command =
        std::process::Command::new(std::env::current_exe().expect("this test binary"));
    command.args(helper_args(name)).env(HELPER_VAR, name);
    command
}

/// The helper's output, after checking that it ran and passed.
///
/// libtest exits 0 both when the helper passed and when the filter matched
/// nothing (a renamed helper), printing "1 passed" or "0 passed": a parent
/// that only reads the exit status passes over a helper that never ran. And
/// "1 passed" alone is also what a helper prints when its guard returned
/// early, so the line [`running_helper`] prints past the guard is required
/// too.
pub fn assert_helper_ran(name: &str, output: &std::process::Output) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "helper {name} failed:\n{text}");
    assert!(
        text.contains("test result: ok. 1 passed"),
        "helper {name} did not run:\n{text}"
    );
    assert!(
        text.lines()
            .any(|line| line.trim_end().ends_with(&format!("{HELPER_RAN} {name}"))),
        "helper {name} passed without getting past its guard ({HELPER_VAR} did not \
         reach it):\n{text}"
    );
    text
}

/// Run helper `name` of this test binary to completion with `env` and
/// return its output ([`helper_command`], [`assert_helper_ran`]).
pub fn rerun_self(name: &str, env: &[(&str, &std::ffi::OsStr)]) -> String {
    let mut command = helper_command(name);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().expect("the helper starts");
    assert_helper_ran(name, &output)
}

// ---------------------------------------------------------------------------
// The precondition every live Linux check shares
// ---------------------------------------------------------------------------

//
// jail-v1 §16: a generic hosted runner runs the portable tests and never
// pretends to exercise a privileged kernel feature. A check that needs the
// backend and a user namespace says so and skips where it cannot have them,
// and under `OURO_CONFORMANCE=1` — the provisioned host — the same call fails
// instead, because there a missing capability is a real result. One answer to
// "can this host run these?", shared by every live suite.

use std::path::PathBuf;
use std::sync::OnceLock;

use ouro_fixture::harness;

/// What the probe established, once per process.
struct Preconditions {
    /// The backend, when it is on `PATH` and works.
    bwrap: Option<PathBuf>,
    /// Why the live checks cannot run here, when they cannot.
    reason: Option<String>,
}

fn preconditions() -> &'static Preconditions {
    static ONCE: OnceLock<Preconditions> = OnceLock::new();
    ONCE.get_or_init(measure)
}

/// Whether this host can run the live checks.
///
/// Prints `skipped: <reason>` and returns false when it cannot, or fails when
/// `OURO_CONFORMANCE=1` says a skip is not an answer. Call it first in every
/// test that needs the backend, and return when it is false.
#[must_use]
pub fn live() -> bool {
    hold_records();
    match preconditions().reason.as_deref() {
        None => true,
        Some(reason) => {
            harness::skip_or_fail(reason);
            false
        }
    }
}

/// The backend this host's live checks use.
///
/// Only meaningful after [`live`] returned true; it never panics, so a caller
/// that forgets gets a failed run rather than a confusing one.
#[must_use]
pub fn bwrap_path() -> PathBuf {
    preconditions()
        .bwrap
        .clone()
        .unwrap_or_else(|| PathBuf::from("bwrap"))
}

/// A claim about the provisioned reference host rather than about Linux.
///
/// The merged-`/usr` layout and the delegated cgroup subtree are properties of
/// the host §3.2 pins, not of the kernel: a generic runner can have the
/// backend and still not be that host. Such a check runs under
/// `OURO_CONFORMANCE=1`, where it is judged, and skips elsewhere with the
/// reason. It is not made conditional on its own assertion, which would be a
/// check that cannot fail.
#[must_use]
pub fn reference_host(what: &str) -> bool {
    hold_records();
    if harness::live_required() {
        return true;
    }
    harness::skip_or_fail(&format!(
        "{what} is a property of the provisioned reference host; \
         set OURO_CONFORMANCE=1 on that host to check it"
    ));
    false
}

/// Whether this host's product probe `name` reports the capability
/// available, measured once per test binary by the product's own probe
/// (`ouro-jail`'s `platform::linux::probe`, the one `doctor` and preparation
/// run) against the backend [`live`] found.
///
/// Composed with [`live`]: a probe is only asked on a host that can run the
/// live checks at all. When the capability is missing, prints `skipped:` with
/// `why` and the probe's evidence, or fails under `OURO_CONFORMANCE=1`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn probe_available(name: &'static str, why: &str) -> bool {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use ouro_jail::platform::linux::probe;

    static MEASURED: Mutex<BTreeMap<&'static str, Result<(), String>>> =
        Mutex::new(BTreeMap::new());
    if !live() {
        return false;
    }
    let measured = MEASURED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(name)
        .or_insert_with(|| {
            let result = probe::run_one(name, &harness::jail_path(), &bwrap_path());
            if result.status == probe::ProbeStatus::Available {
                Ok(())
            } else {
                Err(result.evidence)
            }
        })
        .clone();
    match measured {
        Ok(()) => true,
        Err(evidence) => {
            harness::skip_or_fail(&format!("{why}: {name} is unavailable: {evidence}"));
            false
        }
    }
}

/// Whether this host can run a live check that needs a delegated cgroup
/// leaf: `none`'s tree termination rests on one (§9.3), and so do the
/// lifecycle, scope and GC checks. [`live`], then the product's
/// `cgroup_delegated_leaf` probe ([`probe_available`]).
#[cfg(target_os = "linux")]
#[must_use]
pub fn delegated_leaf() -> bool {
    probe_available(
        "cgroup_delegated_leaf",
        "this check needs a delegated user scope with a usable leaf \
         (run it under `systemd-run --user --scope -p Delegate=yes`)",
    )
}

/// Whether this host can run a live check of `profile`: [`live`], and for
/// `none` a delegated leaf ([`delegated_leaf`]).
#[cfg(target_os = "linux")]
#[must_use]
pub fn profile_live(profile: ouro_jail::policy::ProfileName) -> bool {
    if profile == ouro_jail::policy::ProfileName::None {
        delegated_leaf()
    } else {
        live()
    }
}

/// The interpreter the `none` and orphan fixtures are written in.
pub const PYTHON: &str = "/usr/bin/python3";

/// Whether [`PYTHON`] is installed; prints `skipped:` or fails under
/// `OURO_CONFORMANCE=1` when it is not.
#[must_use]
pub fn python() -> bool {
    if std::path::Path::new(PYTHON).is_file() {
        return true;
    }
    harness::skip_or_fail(&format!(
        "these fixtures are scripts for {PYTHON}, which is absent"
    ));
    false
}

/// Measure, without panicking, whether the live checks can run.
///
/// Off Linux there is nothing to measure: the mechanisms these checks are
/// about do not exist, and the modules that would probe them are not compiled.
#[cfg(not(target_os = "linux"))]
fn measure() -> Preconditions {
    unmet("these checks measure Linux kernel mechanisms")
}

/// Measure, without panicking, whether the live checks can run.
#[cfg(target_os = "linux")]
fn measure() -> Preconditions {
    use std::path::Path;
    use std::process::Command;
    use std::time::Duration;

    let Some(bwrap) = which("bwrap") else {
        return unmet("bubblewrap is not on PATH, so there is no backend to measure");
    };
    let Some(truth) = ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
    else {
        return unmet("this host has no `true` to run inside a sandbox");
    };

    // The binary alone is not the question. A hosted runner can have
    // bubblewrap and still refuse an unprivileged user namespace, which is
    // the capability every one of these checks rests on, so the probe creates
    // one and runs a command in it.
    let mut command = Command::new(&bwrap);
    command.arg("--unshare-user").arg("--unshare-pid");
    for root in ouro_jail::platform::linux::bwrap::RUNTIME_ROOTS
        .iter()
        .filter_map(|path| ouro_jail::platform::linux::fs::resolve_runtime_root(Path::new(path)))
    {
        match root {
            ouro_jail::platform::linux::fs::RootSpec::RoBind(path) => {
                command.arg("--ro-bind").arg(&path).arg(&path);
            }
            ouro_jail::platform::linux::fs::RootSpec::Symlink { path, target } => {
                command.arg("--symlink").arg(&target).arg(&path);
            }
        }
    }
    command.arg("--proc").arg("/proc").arg("--").arg(&truth);

    let deadline = ouro_jail::platform::linux::clock::Deadline::after(Duration::from_secs(10));
    match ouro_jail::platform::linux::exec::run_captured(&mut command, deadline) {
        Ok(run) if run.status.success() => Preconditions {
            bwrap: Some(bwrap),
            reason: None,
        },
        Ok(run) if run.timed_out => unmet("a sandbox probe did not finish in ten seconds"),
        Ok(run) => {
            let detail = run
                .stderr
                .lines()
                .next()
                .unwrap_or("no diagnostic")
                .to_owned();
            unmet(&format!(
                "this host refuses an unprivileged user and pid namespace: {detail}"
            ))
        }
        Err(error) => unmet(&format!("the sandbox probe could not be started: {error}")),
    }
}

fn unmet(reason: &str) -> Preconditions {
    Preconditions {
        bwrap: None,
        reason: Some(reason.to_owned()),
    }
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    })
}

// ---------------------------------------------------------------------------
// The record checks the schema cannot express (R01)
// ---------------------------------------------------------------------------

/// The rules a receipt's schema cannot state, as the library checks them
/// (`ouro_jail::records::semantic::receipt`): canonical native byte
/// strings, unique credential ids and limit keys, a counted class's source
/// not unsupported, and gap intervals in order. `validate_contract.py` holds
/// the port of the same rules, over the same corpus.
///
/// # Errors
/// Every rule the receipt breaks, with its JSON path.
pub fn semantic_receipt(record: &serde_json::Value) -> Result<(), String> {
    violations(&ouro_jail::records::semantic::receipt(record))
}

fn violations(found: &[ouro_jail::records::semantic::Violation]) -> Result<(), String> {
    if found.is_empty() {
        return Ok(());
    }
    Err(found
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; "))
}

/// The bytes a native string names (canonicalization.md, "Native strings").
///
/// # Errors
/// Why the value is not a canonical native string.
pub fn native_bytes(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    ouro_jail::records::semantic::native_bytes(value)
}

/// Every `*.schema.json` in `dir`, by stem.
///
/// A second file declaring an `$id` that another file
/// already declares is refused. The registry keeps one resource per `$id`, so
/// an unfrozen file could otherwise silently replace a frozen schema, with no
/// frozen sha256 changing and the winner decided by directory order.
///
/// # Errors
/// An unreadable or unparsable file, a schema without an `$id`, or two files
/// declaring one `$id`.
pub fn load_schemas(
    dir: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, serde_json::Value>, String> {
    let mut schemas = std::collections::BTreeMap::new();
    let mut owners: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .map_err(|error| format!("{}: {error}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Some(stem) = name.strip_suffix(".schema.json") else {
            continue;
        };
        let bytes = std::fs::read(&path).map_err(|error| format!("{name}: {error}"))?;
        let schema: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|error| format!("{name}: {error}"))?;
        let id = schema["$id"]
            .as_str()
            .ok_or_else(|| format!("{name} declares no $id"))?
            .to_owned();
        if let Some(owner) = owners.insert(id.clone(), name.clone()) {
            return Err(format!(
                "{name} declares {id}, which {owner} already declares: one of them would \
                 silently replace the other"
            ));
        }
        schemas.insert(stem.to_owned(), schema);
    }
    Ok(schemas)
}

/// Every checked-in schema, by stem (`jail-receipt`, `jail-event`, ...), built
/// once per test binary with the cross-schema registry and format checks.
pub fn validators() -> &'static std::collections::BTreeMap<String, jsonschema::Validator> {
    static ONCE: OnceLock<std::collections::BTreeMap<String, jsonschema::Validator>> =
        OnceLock::new();
    ONCE.get_or_init(|| {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/jail-v1");
        let schemas = load_schemas(&dir).unwrap_or_else(|error| panic!("{error}"));
        let resources: Vec<(String, jsonschema::Resource)> = schemas
            .values()
            .map(|schema| {
                (
                    schema["$id"].as_str().expect("an $id").to_owned(),
                    jsonschema::Resource::from_contents(schema.clone()),
                )
            })
            .collect();
        let registry: &'static jsonschema::Registry = Box::leak(Box::new(
            jsonschema::Registry::new()
                .extend(resources)
                .expect("the registry")
                .prepare()
                .expect("the registry"),
        ));
        schemas
            .into_iter()
            .map(|(name, schema)| {
                let validator = jsonschema::options()
                    .with_registry(registry)
                    .should_validate_formats(true)
                    .build(&schema)
                    .expect("a validator");
                (name, validator)
            })
            .collect()
    })
}

/// A receipt the product wrote: schema-valid and semantically valid.
///
/// # Errors
/// Every schema error, or the semantic rule it breaks.
pub fn check_receipt(receipt: &serde_json::Value) -> Result<(), String> {
    let errors: Vec<String> = validators()["jail-receipt"]
        .iter_errors(receipt)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect();
    if !errors.is_empty() {
        return Err(format!("schema: {errors:?}"));
    }
    semantic_receipt(receipt).map_err(|error| format!("semantic: {error}"))
}

/// [`semantic_receipt`] as an assertion, for a product receipt a live test
/// has already validated against the schema: a failure names the rule and
/// prints the receipt. It is a product finding, never a reason to relax it.
pub fn assert_semantic_receipt(receipt: &serde_json::Value) {
    if let Err(error) = semantic_receipt(receipt) {
        panic!("a receipt breaks a rule its schema cannot state: {error}\n{receipt:#}");
    }
}

/// [`check_receipt`] as an assertion, for a product receipt a live test
/// reads: schema and semantic rules. Returns the receipt.
#[must_use]
pub fn checked_receipt(receipt: serde_json::Value) -> serde_json::Value {
    if let Err(error) = check_receipt(&receipt) {
        panic!("a product receipt fails its contract: {error}\n{receipt:#}");
    }
    receipt
}

/// A receipt a test reads from disk itself (a `jail.json` it is about to
/// compare, or to tamper with), held to its contract like one the harness
/// hands out ([`checked_receipt`]).
#[must_use]
pub fn read_receipt(path: &std::path::Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    checked_receipt(
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("{} is not one JSON document: {error}", path.display())),
    )
}

// ---------------------------------------------------------------------------
// Traces, control transcripts and whole runs (R01, §8.2, §13.1, §13.3)
// ---------------------------------------------------------------------------

fn schema_errors(schema: &str, value: &serde_json::Value) -> Vec<String> {
    validators()[schema]
        .iter_errors(value)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect()
}

/// A trace the product wrote: every event schema-valid (`jail-event`), and
/// the stream semantically valid (`ouro_jail::records::semantic::trace`: one
/// attempt, `source_seq` from 1 per source with no silent hole, receipt
/// notes in lifecycle order). With the attempt's final receipt, the stream
/// also ends on that receipt's note (§13.3).
///
/// # Errors
/// Every schema error of the first invalid event, or every semantic rule the
/// stream breaks.
pub fn check_trace(
    events: &[serde_json::Value],
    final_receipt: Option<&serde_json::Value>,
) -> Result<(), String> {
    for (index, event) in events.iter().enumerate() {
        let errors = schema_errors("jail-event", event);
        if !errors.is_empty() {
            return Err(format!("event [{index}] schema: {errors:?}"));
        }
    }
    let mut found = ouro_jail::records::semantic::trace(events);
    if let Some(receipt) = final_receipt {
        found.extend(ouro_jail::records::semantic::trace_ends_with(
            events, receipt,
        ));
    }
    violations(&found).map_err(|error| format!("semantic: {error}"))
}

/// A control transcript the product wrote: every message schema-valid
/// (`jail-control`) and the transcript in order
/// (`ouro_jail::records::semantic::control`).
///
/// # Errors
/// Every schema error of the first invalid message, or every semantic rule
/// the transcript breaks.
pub fn check_control(messages: &[serde_json::Value]) -> Result<(), String> {
    for (index, message) in messages.iter().enumerate() {
        let errors = schema_errors("jail-control", message);
        if !errors.is_empty() {
            return Err(format!("control message [{index}] schema: {errors:?}"));
        }
    }
    violations(&ouro_jail::records::semantic::control(messages))
        .map_err(|error| format!("semantic: {error}"))
}

/// Hold every record the harness hands this test binary to the frozen
/// schemas and the semantic rules: each receipt ([`check_receipt`]), control
/// transcript ([`check_control`]) and complete trace ([`check_trace`]) a
/// `Run` or `Spawned` returns has passed them, or the read panics with the
/// finding. [`live`] installs it, so a live test cannot read a product record
/// that was not checked; the harness refuses to hand out records at all in a
/// binary that installed nothing. Idempotent.
pub fn hold_records() {
    harness::hold_records_to(harness::RecordContract {
        receipt: check_receipt,
        control: check_control,
        trace: check_trace,
    });
}

/// Everything a run wrote, held to its contract: every receipt
/// ([`check_receipt`]), the trace when one was asked for ([`check_trace`],
/// against the attempt's final receipt) and the control transcript
/// ([`check_control`]). Panics with the finding and the record: a failure is
/// a product finding, never a reason to relax a rule.
///
/// The trace is read through `Run::trace_events`, which already refuses a
/// transcript that is not complete in the §13.3 sense; a test about an
/// incomplete trace reads `trace_readback` itself and does not call this.
///
/// The accessors hold what a test reads ([`hold_records`]); this holds what
/// it does not read too, so a run whose trace or transcript breaks a rule
/// fails even when the test only asks about its receipt.
pub fn assert_run_records(run: &harness::Run) {
    hold_records();
    let _ = run.receipts();
    if run.trace_readback.is_some() {
        let _ = run.trace_events();
    }
    let _ = run.control_messages();
}

/// The complete frames of a trace cut short by design (a killed supervisor,
/// a consumer that left), held to what a prefix can keep: every event
/// schema-valid and the stream's rules up to the cut ([`check_trace`] with no
/// final receipt). `Run::trace_events` rightly refuses such a trace, since
/// it does not end on the final receipt's note (§13.3).
pub fn assert_trace_prefix(run: &harness::Run) -> &[serde_json::Value] {
    let readback = run.trace_readback.as_ref().expect("a trace was requested");
    if let Err(error) = check_trace(&readback.frames, None) {
        panic!(
            "the frames of a product trace fail their contract: {error}\n{:#}",
            serde_json::Value::from(readback.frames.clone())
        );
    }
    &readback.frames
}

/// The settled receipt of a run that ended normally, after everything the
/// run wrote passed its contract ([`assert_run_records`]). Called for its
/// assertions alone, it says the run settled with records that hold.
pub fn settled(run: &harness::Run) -> serde_json::Value {
    phase_receipt(run, "settled")
}

/// The last receipt of `phase` a run left, after everything the run wrote
/// passed its contract ([`assert_run_records`]).
#[must_use]
pub fn phase_receipt(run: &harness::Run, phase: &str) -> serde_json::Value {
    assert_run_records(run);
    run.receipt_phase(phase).unwrap_or_else(|| {
        panic!(
            "no {phase} receipt: exit {:?}, phases {:?}, stderr {}",
            run.code(),
            run.receipts()
                .iter()
                .map(|receipt| receipt["phase"].clone())
                .collect::<Vec<_>>(),
            run.stderr_text()
        )
    })
}

/// The receipt the run ended with: the highest revision among the receipts
/// it left, each held to its contract. For a run whose trace or transcript
/// is not whole by design (a consumer that left, a killed supervisor); a run
/// that ended normally reads [`settled`], which holds all of them.
#[must_use]
pub fn last_receipt(run: &harness::Run) -> serde_json::Value {
    hold_records();
    run.receipts()
        .into_iter()
        .max_by_key(|receipt| receipt["revision"].as_u64().unwrap_or(0))
        .unwrap_or_else(|| {
            panic!(
                "no receipt: exit {:?}, stderr {}",
                run.code(),
                run.stderr_text()
            )
        })
}
