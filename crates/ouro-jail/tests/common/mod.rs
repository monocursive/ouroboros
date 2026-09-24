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
/// Every test file uses this, not only the ones that build a state root today:
/// which temporary directory ends up as a state-root ancestor is a detail that
/// changes when a test is edited, and the umask of the machine running it is
/// not something a test should depend on either way.
pub fn private_tempdir() -> TempDir {
    tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .expect("a temporary directory")
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
// "can this host run these?", shared by all three Linux test binaries.

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
    if harness::live_required() {
        return true;
    }
    harness::skip_or_fail(&format!(
        "{what} is a property of the provisioned reference host; \
         set OURO_CONFORMANCE=1 on that host to check it"
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
// J4-R, J5-C: the record checks the schema cannot express (R01)
// ---------------------------------------------------------------------------

/// The rules a receipt's schema cannot state, as the library checks them
/// (`ouro_jail::records::semantic::receipt`, J5-C): canonical native byte
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
/// J5-C review item 1: a second file declaring an `$id` that another file
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

// ---------------------------------------------------------------------------
// J5-C: traces, control transcripts and whole runs (R01, §8.2, §13.1, §13.3)
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

/// Everything a run wrote, held to its contract: every receipt
/// ([`check_receipt`]), the trace when one was asked for ([`check_trace`],
/// against the attempt's final receipt) and the control transcript
/// ([`check_control`]). Panics with the finding and the record: a failure is
/// a product finding, never a reason to relax a rule.
///
/// The trace is read through `Run::trace_events`, which already refuses a
/// transcript that is not complete in the §13.3 sense; a test about an
/// incomplete trace reads `trace_readback` itself and does not call this.
pub fn assert_run_records(run: &harness::Run) {
    for receipt in run.receipts() {
        if let Err(error) = check_receipt(&receipt) {
            panic!("a product receipt fails its contract: {error}\n{receipt:#}");
        }
    }
    if run.trace_readback.is_some() {
        let final_receipt = run
            .final_receipt()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok());
        if let Err(error) = check_trace(run.trace_events(), final_receipt.as_ref()) {
            panic!(
                "a product trace fails its contract: {error}\n{:#}",
                serde_json::Value::from(run.trace_events().to_vec())
            );
        }
    }
    if let Err(error) = check_control(run.control_messages()) {
        panic!(
            "a product control transcript fails its contract: {error}\n{:#}",
            serde_json::Value::from(run.control_messages().to_vec())
        );
    }
}
