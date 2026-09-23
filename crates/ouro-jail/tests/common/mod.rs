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
// J4-R: the receipt checks the schema cannot express (R01)
// ---------------------------------------------------------------------------

/// The Rust port of `validate_contract.py`'s `semantic_receipt`: the receipt
/// rules JSON Schema cannot state, checked on a receipt the schema accepted.
///
/// - every byte-valued native string is canonical padded base64 of bytes that
///   are not valid UTF-8 (those must use the string form) and hold no NUL;
/// - credential ids are unique, and so are `applied.limits` keys;
/// - a coverage class that is not `unsupported` names a source whose observer
///   status is not `unsupported` either.
///
/// # Errors
/// The first rule the receipt breaks, with the JSON path.
pub fn semantic_receipt(record: &serde_json::Value) -> Result<(), String> {
    check_byte_objects(record, "$")?;
    let keys = |list: &serde_json::Value, key: &str, what: &str| -> Result<(), String> {
        let mut seen = std::collections::BTreeSet::new();
        for item in list
            .as_array()
            .ok_or_else(|| format!("{what} is not an array"))?
        {
            let value = item[key].to_string();
            if !seen.insert(value.clone()) {
                return Err(format!("duplicate {what} {value}"));
            }
        }
        Ok(())
    };
    keys(&record["credentials"], "id", "credential id")?;
    keys(&record["applied"]["limits"], "key", "limit")?;
    let coverage = record["coverage"]
        .as_object()
        .ok_or("coverage is not an object")?;
    for (name, class) in coverage {
        if class["status"] == "unsupported" {
            continue;
        }
        let source = class["sources"][0]
            .as_str()
            .ok_or_else(|| format!("coverage {name} is not unsupported but names no source"))?;
        if record["observer"]["sources"][source] == "unsupported" {
            return Err(format!(
                "coverage {name} counts from source {source}, which the observer reports unsupported"
            ));
        }
    }
    Ok(())
}

fn check_byte_objects(node: &serde_json::Value, at: &str) -> Result<(), String> {
    match node {
        serde_json::Value::Object(map) => {
            if map.get("encoding").and_then(serde_json::Value::as_str) == Some("base64") {
                return native_bytes(node)
                    .map(|_| ())
                    .map_err(|error| format!("{at}: {error}"));
            }
            for (key, value) in map {
                check_byte_objects(value, &format!("{at}.{key}"))?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                check_byte_objects(value, &format!("{at}[{index}]"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The bytes a native string names (canonicalization.md, "Native strings").
///
/// # Errors
/// Why the value is not a canonical native string.
pub fn native_bytes(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let raw = match value {
        serde_json::Value::String(text) => text.as_bytes().to_vec(),
        serde_json::Value::Object(map) => {
            let keys: Vec<&str> = map.keys().map(String::as_str).collect();
            if keys != ["data", "encoding"] {
                return Err(format!("a byte object has the keys {keys:?}"));
            }
            if map["encoding"] != "base64" {
                return Err("a byte object's encoding is not base64".to_owned());
            }
            let data = map["data"]
                .as_str()
                .ok_or("a byte object's data is not a string")?;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|error| format!("the base64 does not decode: {error}"))?;
            if base64::engine::general_purpose::STANDARD.encode(&raw) != data {
                return Err("the base64 is not canonical".to_owned());
            }
            if std::str::from_utf8(&raw).is_ok() {
                return Err("UTF-8 bytes must use the JSON string form".to_owned());
            }
            raw
        }
        other => return Err(format!("{other} is not a native string")),
    };
    if raw.contains(&0) {
        return Err("a native value contains NUL".to_owned());
    }
    Ok(raw)
}

/// Every checked-in schema, by stem (`jail-receipt`, `jail-event`, ...), built
/// once per test binary with the cross-schema registry and format checks.
pub fn validators() -> &'static std::collections::BTreeMap<String, jsonschema::Validator> {
    static ONCE: OnceLock<std::collections::BTreeMap<String, jsonschema::Validator>> =
        OnceLock::new();
    ONCE.get_or_init(|| {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/jail-v1");
        let mut schemas = std::collections::BTreeMap::new();
        for entry in std::fs::read_dir(&dir).expect("the specification directory") {
            let path = entry.expect("an entry").path();
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            if let Some(stem) = name.strip_suffix(".schema.json") {
                let schema: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).expect("a schema"))
                        .expect("a JSON schema");
                schemas.insert(stem.to_owned(), schema);
            }
        }
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
