//! `cargo xtask freeze`: the milestone-1 freeze file (jail-v1 §16).
//!
//! §16: "Freeze the Rust toolchain, Cargo.lock, backend version/hashes,
//! filter digest, observer object/build provenance and tested host manifest
//! with the milestone report. Re-run relevant conformance when any of these
//! change. A dependency update must not silently broaden mounted files or
//! allow-hosts."
//!
//! This writes `docs/specs/jail-v1/milestone-1-freeze.toml` from the tree:
//! the pinned toolchain, the lock file's hash, every manifest's profiles,
//! dependency selections and features, the filter and closed-set digests
//! from the checked-in evidence tables, the contained mount baselines, the
//! contained environment, each built-in profile's resolved baseline, the
//! backend plan each contained profile renders (on Linux), the bundled
//! launch profiles' mounts, environment and allowed hosts, and the frozen
//! schemas (`frozen-schemas.toml`, when it exists). With `--doctor`, it also
//! records the tested run, validated strictly (see [`validate_tested`]).
//! `crates/ouro-jail/tests/portable_freeze.rs` fails when an in-tree value
//! drifts from the file; `cargo xtask freeze --check` is the milestone gate:
//! it fails unless the file is exactly what this tree generates and records
//! a valid tested run of this very tree.
//!
//! Values come from files and from the jail's own rendering functions
//! (`ouro_jail::platform::linux::freeze`), the same ones the test calls.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

// The build-input digest rule `build.rs` applies, so a tested binary's
// `inputs` can be recomputed from the tree and from a commit.
#[allow(dead_code)]
#[path = "../../ouro-jail/src/build_provenance.rs"]
mod build_provenance;

/// Where the freeze file lives, relative to the repository root.
pub const FREEZE_PATH: &str = "docs/specs/jail-v1/milestone-1-freeze.toml";
/// The freeze file's own identifier.
pub const SCHEMA: &str = "ouro.jail.milestone-freeze/1";
/// The line that separates the tree's values from the tested run.
pub const TESTED_MARKER: &str =
    "# --- the tested run (cargo xtask freeze --doctor); everything above is the tree ---";

/// The frozen inputs that are not build inputs, as git pathspecs: a change
/// to any of them after the tested revision means the run did not test what
/// the file freezes. (Build inputs are compared by digest.)
const FROZEN_PATHSPECS: [&str; 5] = [
    "docs/specs/jail-v1/evidence",
    "docs/specs/jail-v1/frozen-schemas.toml",
    "docs/specs/jail-v1/*.schema.json",
    "crates/ouro-jail/profiles/launch",
    "crates/*/Cargo.toml",
];

/// The evidence tables whose digests the freeze pins, by freeze key.
/// Each table ends every program's listing with a `digest: sha256:...`
/// line; the agent tables list the agent baseline first and the mediation
/// filter second.
const FILTER_TABLES: [(&str, &str, usize); 4] = [
    ("tool", "seccomp-table-tool-x86_64.txt", 0),
    ("agent", "seccomp-table-agent-x86_64.txt", 0),
    (
        "agent_namespace",
        "seccomp-table-agent-namespace-x86_64.txt",
        0,
    ),
    ("agent_mediation", "seccomp-table-agent-x86_64.txt", 1),
];
const CLOSED_SET_TABLE: &str = "closed-set-x86_64.txt";
const EVIDENCE: &str = "docs/specs/jail-v1/evidence";
const LAUNCH_DIR: &str = "crates/ouro-jail/profiles/launch";
const FROZEN_SCHEMAS: &str = "docs/specs/jail-v1/frozen-schemas.toml";

/// The Rust constants that are the contained mount baselines, by freeze
/// key: `(key, source file, constant name)`.
const MOUNT_CONSTANTS: [(&str, &str, &str); 4] = [
    (
        "linux_runtime_roots",
        "crates/ouro-jail/src/profiles.rs",
        "LINUX_RUNTIME_ROOTS",
    ),
    (
        "protected_segments",
        "crates/ouro-jail/src/profiles.rs",
        "PROTECTED_SEGMENTS",
    ),
    (
        "backend_runtime_roots",
        "crates/ouro-jail/src/platform/linux/bwrap.rs",
        "RUNTIME_ROOTS",
    ),
    (
        "backend_etc_paths",
        "crates/ouro-jail/src/platform/linux/bwrap.rs",
        "ETC_PATHS",
    ),
];

fn read(root: &Path, relative: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(relative)).map_err(|error| format!("{relative}: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A TOML basic string. JSON's escapes (`\"`, `\\`, `\n`, `\uXXXX`) are all
/// valid in a TOML basic string.
fn quote(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned())
}

fn quote_list(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|item| quote(item)).collect();
    format!("[{}]", quoted.join(", "))
}

/// The `n`th `digest: sha256:...` value in an evidence table (a line that
/// starts with `digest:` or ends a `... digest: sha256:` phrase).
pub fn nth_digest(table: &str, n: usize) -> Option<String> {
    table
        .lines()
        .filter_map(|line| {
            let (_, value) = line.split_once("digest: ")?;
            let value = value.trim();
            (value.starts_with("sha256:")
                && value.len() == 71
                && value[7..].bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| value.to_owned())
        })
        .nth(n)
}

/// The string literals of a `const NAME: ... = [ ... ];` (or `&[ ... ]`) in
/// Rust source. The constants the freeze pins are flat lists of plain
/// string literals; anything else is an error, not a guess.
pub fn const_string_list(source: &str, name: &str) -> Result<Vec<String>, String> {
    let marker = format!("const {name}:");
    let start = source
        .find(&marker)
        .ok_or_else(|| format!("no `const {name}:`"))?;
    let rest = &source[start..];
    let equals = rest
        .find('=')
        .ok_or_else(|| format!("{name} has no value"))?;
    let open = rest[equals..]
        .find('[')
        .map(|at| equals + at)
        .ok_or_else(|| format!("{name} is not a list"))?;
    let close = rest[open..]
        .find("];")
        .map(|at| open + at)
        .ok_or_else(|| format!("{name}'s list does not end"))?;
    let body = &rest[open + 1..close];
    let mut out = Vec::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                let mut literal = String::new();
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => return Err(format!("{name} has an escaped literal")),
                        Some(other) => literal.push(other),
                        None => return Err(format!("{name} has an unterminated literal")),
                    }
                }
                out.push(literal);
            }
            ',' | ' ' | '\n' | '\r' | '\t' => {}
            '/' if chars.peek() == Some(&'/') => {
                // A line comment inside the list.
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
            }
            other => return Err(format!("{name} has `{other}` where a literal belongs")),
        }
    }
    if out.is_empty() {
        return Err(format!("{name} is empty"));
    }
    Ok(out)
}

fn toml_value(root: &Path, relative: &str) -> Result<toml::Value, String> {
    toml::from_str(&read(root, relative)?).map_err(|error| format!("{relative}: {error}"))
}

fn string_at<'a>(value: &'a toml::Value, path: &[&str], file: &str) -> Result<&'a str, String> {
    let mut node = value;
    for key in path {
        node = node
            .get(key)
            .ok_or_else(|| format!("{file}: no `{}`", path.join(".")))?;
    }
    node.as_str()
        .ok_or_else(|| format!("{file}: `{}` is not a string", path.join(".")))
}

fn strings(value: Option<&toml::Value>, what: &str) -> Result<Vec<String>, String> {
    match value {
        None => Ok(Vec::new()),
        Some(value) => value
            .as_array()
            .ok_or_else(|| format!("{what} is not a list"))?
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{what} holds a non-string"))
            })
            .collect(),
    }
}

/// The freeze file's values for the tree at `root`: everything but the
/// tested run.
///
/// # Errors
/// Any value that cannot be read or is not what the freeze expects.
pub fn tree_part(root: &Path) -> Result<String, String> {
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(
        w,
        "# Milestone-1 freeze (jail-v1 §16). Generated by `cargo xtask freeze`;"
    );
    let _ = writeln!(
        w,
        "# do not edit by hand. crates/ouro-jail/tests/portable_freeze.rs fails"
    );
    let _ = writeln!(
        w,
        "# when an in-tree value drifts from this file: a change to any of them"
    );
    let _ = writeln!(
        w,
        "# needs the conformance rerun §16 requires, then a new `cargo xtask"
    );
    let _ = writeln!(w, "# freeze --doctor <that run's doctor.json>`.");
    let _ = writeln!(w, "schema = {}", quote(SCHEMA));
    let _ = writeln!(w, "milestone = 1");

    // The toolchain.
    let toolchain = toml_value(root, "rust-toolchain.toml")?;
    let workspace = toml_value(root, "Cargo.toml")?;
    let _ = writeln!(
        w,
        "\n# rust-toolchain.toml and Cargo.toml [workspace.package]"
    );
    let _ = writeln!(w, "[toolchain]");
    let _ = writeln!(
        w,
        "channel = {}",
        quote(string_at(
            &toolchain,
            &["toolchain", "channel"],
            "rust-toolchain.toml"
        )?)
    );
    let _ = writeln!(
        w,
        "rust_version = {}",
        quote(string_at(
            &workspace,
            &["workspace", "package", "rust-version"],
            "Cargo.toml"
        )?)
    );

    // The lock file.
    let lock = std::fs::read(root.join("Cargo.lock")).map_err(|e| format!("Cargo.lock: {e}"))?;
    let lock_value: toml::Value = toml::from_str(&String::from_utf8_lossy(&lock))
        .map_err(|error| format!("Cargo.lock: {error}"))?;
    let packages = lock_value
        .get("package")
        .and_then(toml::Value::as_array)
        .map_or(0, Vec::len);
    let _ = writeln!(w, "\n# Cargo.lock, byte for byte");
    let _ = writeln!(w, "[cargo_lock]");
    let _ = writeln!(w, "sha256 = {}", quote(&sha256_hex(&lock)));
    let _ = writeln!(w, "packages = {packages}");

    // The filters, from the checked-in evidence tables.
    let _ = writeln!(
        w,
        "\n# The seccomp programs' digests, from {EVIDENCE}/seccomp-table-*.txt"
    );
    let _ = writeln!(w, "[filters]");
    let _ = writeln!(w, "arch = \"x86_64\"");
    for (key, table, index) in FILTER_TABLES {
        let text = read(root, &format!("{EVIDENCE}/{table}"))?;
        let digest =
            nth_digest(&text, index).ok_or_else(|| format!("{table}: no digest #{index}"))?;
        let _ = writeln!(w, "{key} = {}", quote(&digest));
    }
    let _ = writeln!(w, "\n# The evidence tables themselves, byte for byte");
    let _ = writeln!(w, "[filters.table_sha256]");
    let mut seen = std::collections::BTreeSet::new();
    for (_, table, _) in FILTER_TABLES {
        if seen.insert(table) {
            let bytes = std::fs::read(root.join(EVIDENCE).join(table))
                .map_err(|error| format!("{table}: {error}"))?;
            let _ = writeln!(w, "{} = {}", quote(table), quote(&sha256_hex(&bytes)));
        }
    }

    // The closed set.
    let closed = read(root, &format!("{EVIDENCE}/{CLOSED_SET_TABLE}"))?;
    let narrowing =
        nth_digest(&closed, 0).ok_or_else(|| format!("{CLOSED_SET_TABLE}: no digest"))?;
    let _ = writeln!(
        w,
        "\n# The observer's closed set, from {EVIDENCE}/{CLOSED_SET_TABLE}"
    );
    let _ = writeln!(w, "[closed_set]");
    let _ = writeln!(w, "name = \"linux-closed-v1\"");
    let _ = writeln!(w, "narrowing_filter = {}", quote(&narrowing));
    let _ = writeln!(
        w,
        "table_sha256 = {}",
        quote(&sha256_hex(closed.as_bytes()))
    );

    // The contained mount baselines.
    let _ = writeln!(
        w,
        "\n# The contained mount baselines: what every contained profile mounts"
    );
    let _ = writeln!(w, "[mounts]");
    for (key, file, name) in MOUNT_CONSTANTS {
        let values = const_string_list(&read(root, file)?, name)
            .map_err(|error| format!("{file}: {error}"))?;
        let _ = writeln!(w, "# {file} {name}");
        let _ = writeln!(w, "{key} = {}", quote_list(&values));
    }

    // The bundled launch profiles.
    let mut files: Vec<PathBuf> = std::fs::read_dir(root.join(LAUNCH_DIR))
        .map_err(|error| format!("{LAUNCH_DIR}: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    files.sort();
    let _ = writeln!(
        w,
        "\n# The bundled launch profiles ({LAUNCH_DIR}): what each one mounts or\n\
         # copies into the sandbox, and the hosts it allows."
    );
    for path in files {
        let file = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        let profile = toml_value(root, &file)?;
        let _ = writeln!(w, "\n[[launch_profile]]");
        let _ = writeln!(w, "file = {}", quote(&file));
        let _ = writeln!(
            w,
            "name = {}",
            quote(string_at(&profile, &["name"], &file)?)
        );
        let _ = writeln!(
            w,
            "jail = {}",
            quote(string_at(&profile, &["jail"], &file)?)
        );
        if let Some(state_var) = profile.get("state_var").and_then(toml::Value::as_str) {
            let _ = writeln!(w, "state_var = {}", quote(state_var));
        }
        let home_is_state = profile
            .get("home_is_state")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        let _ = writeln!(w, "home_is_state = {home_is_state}");
        let subdirs = strings(
            profile.get("state_subdirs"),
            &format!("{file}: state_subdirs"),
        )?;
        let _ = writeln!(w, "state_subdirs = {}", quote_list(&subdirs));
        let allow = strings(
            profile
                .get("network")
                .and_then(|network| network.get("allow")),
            &format!("{file}: network.allow"),
        )?;
        let _ = writeln!(w, "network_allow = {}", quote_list(&allow));
        // The environment it sets in the sandbox (review F3: a preload or a
        // host path here broadens what the child reaches).
        let environment = profile
            .get("environment")
            .map_or_else(|| serde_json::json!({}), json_of_toml);
        let _ = writeln!(
            w,
            "environment = {}",
            quote(&ouro_jail::platform::linux::freeze::canonical_json(
                &environment,
                false
            ))
        );
        if let Some(credentials) = profile.get("credentials").and_then(toml::Value::as_table) {
            for (id, credential) in credentials {
                let _ = writeln!(w, "[[launch_profile.credential]]");
                let _ = writeln!(w, "id = {}", quote(id));
                for key in ["source", "dest", "mode"] {
                    let value = credential
                        .get(key)
                        .and_then(toml::Value::as_str)
                        .ok_or_else(|| format!("{file}: credential {id} has no {key}"))?;
                    let _ = writeln!(w, "{key} = {}", quote(value));
                }
            }
        }
    }

    // The contained environment (review F3).
    let _ = writeln!(
        w,
        "\n# What every contained profile passes from the operator's environment, and its PATH"
    );
    let _ = writeln!(w, "[contained]");
    let names: Vec<String> = ouro_jail::profiles::CONTAINED_ENVIRONMENT_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let _ = writeln!(w, "environment_names = {}", quote_list(&names));
    let _ = writeln!(w, "path = {}", quote(ouro_jail::profiles::CONTAINED_PATH));

    // Each built-in profile's resolved baseline (review F3).
    let _ = writeln!(
        w,
        "\n# Each built-in profile resolved on Linux with fixed inputs (workspace /work,\n\
         # managed scratch, no layer): what it grants, as its canonical snapshot"
    );
    let baselines = ouro_jail::platform::linux::freeze::baselines()
        .map_err(|error| format!("the built-in baselines: {error}"))?;
    for baseline in baselines {
        let snapshot = ouro_jail::platform::linux::freeze::canonical_json(&baseline.snapshot, true);
        let _ = writeln!(w, "\n[[baseline]]");
        let _ = writeln!(w, "profile = {}", quote(baseline.profile.as_str()));
        let _ = writeln!(w, "digest = {}", quote(&baseline.digest));
        let _ = writeln!(w, "snapshot = {}", literal(&snapshot)?);
    }

    // The backend plan each contained profile renders (review F3).
    let _ = writeln!(
        w,
        "\n# The bubblewrap invocation each contained profile's plan renders to\n\
         # (ouro_jail::platform::linux::freeze::backend_plans; generated on Linux)"
    );
    w.push_str(&backend_plan_section(root)?);

    // Every manifest's profiles, dependency selections and features (F14).
    let _ = writeln!(
        w,
        "\n# Every Cargo manifest's [profile.*], dependency tables (versions, features,\n\
         # default-features) and [features], as canonical JSON"
    );
    for file in manifests(root)? {
        let manifest = toml_value(root, &file)?;
        let _ = writeln!(w, "\n[[manifest]]");
        let _ = writeln!(w, "file = {}", quote(&file));
        let sections =
            ouro_jail::platform::linux::freeze::canonical_json(&manifest_sections(&manifest), true);
        let _ = writeln!(w, "sections = {}", literal(&sections)?);
    }

    // The frozen schemas.
    let _ = writeln!(
        w,
        "\n# The frozen wire schemas, from {FROZEN_SCHEMAS} (J5-C); empty until it exists."
    );
    let _ = writeln!(w, "[frozen_schemas]");
    if root.join(FROZEN_SCHEMAS).exists() {
        let frozen = toml_value(root, FROZEN_SCHEMAS)?;
        let _ = writeln!(w, "source = {}", quote(FROZEN_SCHEMAS));
        for entry in frozen
            .get("frozen")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let table = entry
                .as_table()
                .ok_or_else(|| format!("{FROZEN_SCHEMAS}: a [[frozen]] entry is not a table"))?;
            let _ = writeln!(w, "[[frozen_schemas.entry]]");
            for (key, value) in table {
                let value = value.as_str().ok_or_else(|| {
                    format!("{FROZEN_SCHEMAS}: [[frozen]] `{key}` is not a string")
                })?;
                let _ = writeln!(w, "{key} = {}", quote(value));
            }
        }
    }

    Ok(out)
}

/// A TOML multi-line literal string, for a multi-line rendering whose
/// changes should read line by line in a diff.
fn literal(text: &str) -> Result<String, String> {
    if text.contains("'''") {
        return Err("a rendering contains ''' and cannot be a literal string".to_owned());
    }
    Ok(format!("'''\n{text}\n'''"))
}

/// A TOML value as JSON (tables become objects).
fn json_of_toml(value: &toml::Value) -> serde_json::Value {
    match value {
        toml::Value::String(text) => serde_json::Value::String(text.clone()),
        toml::Value::Integer(number) => serde_json::Value::from(*number),
        toml::Value::Float(number) => serde_json::Value::from(*number),
        toml::Value::Boolean(flag) => serde_json::Value::Bool(*flag),
        toml::Value::Datetime(time) => serde_json::Value::String(time.to_string()),
        toml::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(json_of_toml).collect())
        }
        toml::Value::Table(table) => serde_json::Value::Object(
            table
                .iter()
                .map(|(key, value)| (key.clone(), json_of_toml(value)))
                .collect(),
        ),
    }
}

/// The workspace's Cargo manifests: the root and each crate's, sorted.
fn manifests(root: &Path) -> Result<Vec<String>, String> {
    let mut files = vec!["Cargo.toml".to_owned()];
    let mut crates: Vec<String> = std::fs::read_dir(root.join("crates"))
        .map_err(|error| format!("crates: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("Cargo.toml"))
        .filter(|path| path.is_file())
        .map(|path| {
            path.strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    crates.sort();
    files.extend(crates);
    Ok(files)
}

/// The parts of a manifest that decide what is built and how: its
/// profiles, every dependency table (plain, dev, build, target-specific and
/// the workspace's) with versions, features and default-features, and its
/// feature definitions, patches and replacements.
pub fn manifest_sections(manifest: &toml::Value) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for key in [
        "profile",
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "target",
        "features",
        "patch",
        "replace",
    ] {
        if let Some(value) = manifest.get(key) {
            out.insert(key.to_owned(), json_of_toml(value));
        }
    }
    if let Some(value) = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
    {
        out.insert("workspace.dependencies".to_owned(), json_of_toml(value));
    }
    serde_json::Value::Object(out)
}

/// The backend plans, rendered here on Linux; elsewhere the section of the
/// existing freeze file is kept as it is, since only a Linux build has the
/// backend to render (the Linux test legs check it).
fn backend_plan_section(root: &Path) -> Result<String, String> {
    let mut out = String::new();
    #[cfg(target_os = "linux")]
    {
        let plans = ouro_jail::platform::linux::freeze::backend_plans()?;
        for (profile, argv) in plans {
            let _ = writeln!(out, "\n[[backend_plan]]");
            let _ = writeln!(out, "profile = {}", quote(profile));
            let _ = writeln!(out, "argv = [");
            for arg in argv {
                let _ = writeln!(out, "  {},", quote(&arg));
            }
            let _ = writeln!(out, "]");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let existing = std::fs::read_to_string(root.join(FREEZE_PATH)).unwrap_or_default();
        let start = existing.find("\n[[backend_plan]]");
        let end = existing.find("\n# Every Cargo manifest's");
        match (start, end) {
            (Some(start), Some(end)) if start < end => out.push_str(&existing[start..end]),
            _ => {
                return Err(
                    "the backend plans are rendered only on Linux and the existing freeze file \
                     has none to keep: run `cargo xtask freeze` on Linux"
                        .to_owned(),
                );
            }
        }
    }
    let _ = root;
    Ok(out)
}

/// The facts of a tested run that decide whether it tested this tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tested {
    /// `ready` of the run's doctor.
    pub ready: Option<bool>,
    /// `platform.os`.
    pub os: Option<String>,
    /// `platform.arch`.
    pub arch: Option<String>,
    /// `build.target`.
    pub target: Option<String>,
    /// `build.opt_level`.
    pub opt_level: Option<String>,
    /// `build.debug_assertions`.
    pub debug_assertions: Option<bool>,
    /// `build.revision`.
    pub revision: Option<String>,
    /// `build.dirty`.
    pub dirty: Option<bool>,
    /// `build.inputs`.
    pub inputs: Option<String>,
    /// Whether a backend was resolved.
    pub backend: bool,
}

impl Tested {
    /// From a conformance run's `doctor --json`.
    #[must_use]
    pub fn from_doctor(doctor: &serde_json::Value) -> Self {
        let text = |value: &serde_json::Value| value.as_str().map(str::to_owned);
        Tested {
            ready: doctor["ready"].as_bool(),
            os: text(&doctor["platform"]["os"]),
            arch: text(&doctor["platform"]["arch"]),
            target: text(&doctor["build"]["target"]),
            opt_level: text(&doctor["build"]["opt_level"]),
            debug_assertions: doctor["build"]["debug_assertions"].as_bool(),
            revision: text(&doctor["build"]["revision"]),
            dirty: doctor["build"]["dirty"].as_bool(),
            inputs: text(&doctor["build"]["inputs"]),
            backend: doctor["binaries"]["bwrap"].is_object(),
        }
    }

    /// From a freeze file's `[tested]` table.
    #[must_use]
    pub fn from_toml(tested: &toml::Value) -> Self {
        let text = |key: &str| {
            tested
                .get(key)
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        };
        let flag = |key: &str| tested.get(key).and_then(toml::Value::as_bool);
        Tested {
            ready: flag("ready"),
            os: text("platform_os"),
            arch: text("platform_arch"),
            target: text("target"),
            opt_level: text("opt_level"),
            debug_assertions: flag("debug_assertions"),
            revision: text("revision"),
            dirty: flag("dirty"),
            inputs: text("inputs"),
            backend: tested.get("backend").is_some_and(toml::Value::is_table),
        }
    }
}

fn git(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| output.stdout)
}

/// The build-input digest of `revision`'s tree, from git's objects.
fn revision_inputs(root: &Path, revision: &str) -> Result<String, String> {
    let listing = git(
        root,
        &[
            "ls-tree",
            "-r",
            "-z",
            "--name-only",
            revision,
            "--",
            build_provenance::INPUT_DIR,
        ],
    )
    .ok_or_else(|| format!("git cannot list {revision}"))?;
    let mut files: Vec<String> = String::from_utf8_lossy(&listing)
        .split('\0')
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    files.extend(
        build_provenance::INPUT_FILES
            .iter()
            .map(|f| (*f).to_owned()),
    );
    files.sort();
    let mut contents = Vec::with_capacity(files.len());
    for file in &files {
        contents.push(
            git(root, &["cat-file", "blob", &format!("{revision}:{file}")])
                .ok_or_else(|| format!("git has no {file} at {revision}"))?,
        );
    }
    Ok(build_provenance::digest(
        files
            .iter()
            .map(String::as_str)
            .zip(contents.iter().map(Vec::as_slice)),
    ))
}

/// Whether a tested run is the milestone run of the tree at `root` (review
/// F4). It must be ready, on Linux x86_64, optimised without debug
/// assertions, from a named clean revision, and built from exactly this
/// tree's build inputs. Where the repository's `.git` is present, the
/// revision must be an ancestor of `HEAD`, its own inputs must be the
/// binary's (so the revision claim is true), and no other frozen input may
/// have changed since it.
///
/// # Errors
/// Every rule the run breaks.
pub fn validate_tested(root: &Path, tested: &Tested) -> Result<Vec<&'static str>, Vec<String>> {
    let mut problems = Vec::new();
    let mut verified = Vec::new();
    let mut expect = |ok: bool, what: String| {
        if !ok {
            problems.push(what);
        }
    };
    expect(
        tested.ready == Some(true),
        format!("ready is {:?}, not true", tested.ready),
    );
    expect(
        tested.os.as_deref() == Some("linux") && tested.arch.as_deref() == Some("x86_64"),
        format!(
            "the platform is {:?}/{:?}, not linux/x86_64",
            tested.os, tested.arch
        ),
    );
    expect(
        tested.target.as_deref() == Some("x86_64-unknown-linux-gnu"),
        format!("the target is {:?}", tested.target),
    );
    expect(
        tested.opt_level.as_deref() == Some("3") && tested.debug_assertions == Some(false),
        format!(
            "the build is opt-level {:?} with debug assertions {:?}, not an optimised release",
            tested.opt_level, tested.debug_assertions
        ),
    );
    expect(
        tested.dirty == Some(false),
        format!("dirty is {:?}, not false", tested.dirty),
    );
    expect(tested.backend, "no bubblewrap was resolved".to_owned());
    let revision = tested
        .revision
        .as_deref()
        .filter(|revision| build_provenance::validate(Some(revision), None).is_ok());
    expect(
        revision.is_some(),
        format!("the revision {:?} is not a full commit", tested.revision),
    );
    match (
        build_provenance::tree_digest(root),
        tested.inputs.as_deref(),
    ) {
        (Ok(tree), Some(inputs)) if tree == inputs => verified.push("inputs_match_tree"),
        (Ok(tree), inputs) => problems.push(format!(
            "the tested binary was built from inputs {inputs:?}, this tree's are {tree}: \
             re-run the conformance suite on this tree"
        )),
        (Err(error), _) => problems.push(format!("this tree's build inputs: {error}")),
    }
    if let Some(revision) = revision
        && root.join(".git").exists()
    {
        if git(root, &["merge-base", "--is-ancestor", revision, "HEAD"]).is_some() {
            verified.push("revision_is_ancestor_of_head");
        } else {
            problems.push(format!("{revision} is not an ancestor of HEAD"));
        }
        match revision_inputs(root, revision) {
            Ok(digest) if Some(digest.as_str()) == tested.inputs.as_deref() => {
                verified.push("inputs_match_revision");
            }
            Ok(digest) => problems.push(format!(
                "{revision}'s build inputs are {digest}, not the tested binary's {:?}: the \
                 revision claim is false or the tree was dirty",
                tested.inputs
            )),
            Err(error) => problems.push(error),
        }
        let mut args = vec!["diff", "--quiet", revision, "HEAD", "--"];
        args.extend(FROZEN_PATHSPECS);
        if git(root, &args).is_some() {
            verified.push("frozen_inputs_unchanged_since_revision");
        } else {
            problems.push(format!(
                "a frozen input changed since {revision} (git diff {revision} HEAD -- {})",
                FROZEN_PATHSPECS.join(" ")
            ));
        }
    }
    if problems.is_empty() {
        Ok(verified)
    } else {
        Err(problems)
    }
}

/// A JSON value as TOML: objects become tables, and every null is left out
/// and named in `unknown` by its dotted path (never written as a value).
fn toml_of_json(
    value: &serde_json::Value,
    path: &str,
    unknown: &mut Vec<String>,
) -> Option<toml::Value> {
    match value {
        serde_json::Value::Null => {
            unknown.push(path.to_owned());
            None
        }
        serde_json::Value::Bool(flag) => Some(toml::Value::Boolean(*flag)),
        serde_json::Value::Number(number) => Some(
            number
                .as_i64()
                .map(toml::Value::Integer)
                .or_else(|| number.as_f64().map(toml::Value::Float))
                .unwrap_or_else(|| toml::Value::String(number.to_string())),
        ),
        serde_json::Value::String(text) => Some(toml::Value::String(text.clone())),
        serde_json::Value::Array(items) => Some(toml::Value::Array(
            items
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    toml_of_json(item, &format!("{path}[{index}]"), unknown)
                })
                .collect(),
        )),
        serde_json::Value::Object(map) => {
            let mut table = toml::map::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                if let Some(value) = toml_of_json(&map[key], &format!("{path}.{key}"), unknown) {
                    table.insert(key.clone(), value);
                }
            }
            Some(toml::Value::Table(table))
        }
    }
}

/// The `[tested]` section for a validated conformance run's doctor record:
/// the build, the binaries, the full host object and the supervisor scope,
/// with the checks it passed and the facts that were unknown.
///
/// # Errors
/// The rules the run breaks.
pub fn tested_section(root: &Path, doctor: &serde_json::Value) -> Result<String, String> {
    if doctor["schema"] != "ouro.jail.doctor/1" {
        return Err("the --doctor file is not an ouro.jail.doctor/1 record".to_owned());
    }
    let verified = validate_tested(root, &Tested::from_doctor(doctor))
        .map_err(|problems| format!("the tested run is refused:\n  {}", problems.join("\n  ")))?;
    let mut unknown = Vec::new();
    let mut tested = toml::map::Map::new();
    let mut put = |key: &str, value: &serde_json::Value, unknown: &mut Vec<String>| {
        if let Some(value) = toml_of_json(value, key, unknown) {
            tested.insert(key.to_owned(), value);
        }
    };
    put("ready", &doctor["ready"], &mut unknown);
    put("platform_os", &doctor["platform"]["os"], &mut unknown);
    put("platform_arch", &doctor["platform"]["arch"], &mut unknown);
    put(
        "platform_kernel",
        &doctor["platform"]["kernel"],
        &mut unknown,
    );
    for key in [
        "revision",
        "dirty",
        "rustc",
        "target",
        "opt_level",
        "debug_assertions",
        "inputs",
    ] {
        put(key, &doctor["build"][key], &mut unknown);
    }
    put(
        "ouro_jail_sha256",
        &doctor["binaries"]["ouro-jail"]["sha256"],
        &mut unknown,
    );
    put("backend", &doctor["binaries"]["bwrap"], &mut unknown);
    put("host", &doctor["host"], &mut unknown);
    put(
        "supervisor_scope",
        &doctor["supervisor_scope"],
        &mut unknown,
    );
    tested.insert(
        "verification".to_owned(),
        toml::Value::Array(
            verified
                .iter()
                .map(|check| toml::Value::String((*check).to_owned()))
                .collect(),
        ),
    );
    tested.insert(
        "unknown".to_owned(),
        toml::Value::Array(unknown.into_iter().map(toml::Value::String).collect()),
    );
    let mut document = toml::map::Map::new();
    document.insert("tested".to_owned(), toml::Value::Table(tested));
    toml::to_string(&toml::Value::Table(document)).map_err(|error| error.to_string())
}

/// The freeze file for the tree at `root`. With `doctor`, the tested run is
/// validated and recorded; without it, the existing file's tested run is
/// kept when it still validates against this tree and dropped (with a
/// note) when it does not.
///
/// # Errors
/// A value that cannot be read, or a tested run that is refused.
pub fn generate(
    root: &Path,
    doctor: Option<&serde_json::Value>,
) -> Result<(String, Vec<String>), String> {
    let mut text = tree_part(root)?;
    let mut notes = Vec::new();
    let tested = match doctor {
        Some(doctor) => Some(tested_section(root, doctor)?),
        None => {
            let existing = std::fs::read_to_string(root.join(FREEZE_PATH)).unwrap_or_default();
            match existing.split_once(TESTED_MARKER) {
                Some((_, section)) => {
                    let value: toml::Value = toml::from_str(section)
                        .map_err(|error| format!("the existing tested run: {error}"))?;
                    match value.get("tested").map(Tested::from_toml) {
                        Some(tested) if validate_tested(root, &tested).is_ok() => {
                            Some(section.trim_start_matches('\n').to_owned())
                        }
                        _ => {
                            notes.push(
                                "the recorded tested run no longer validates against this tree \
                                 and was dropped; record the next conformance run with --doctor"
                                    .to_owned(),
                            );
                            None
                        }
                    }
                }
                None => None,
            }
        }
    };
    match tested {
        Some(section) => {
            let _ = writeln!(text, "\n{TESTED_MARKER}");
            text.push_str(&section);
        }
        None => {
            let _ = writeln!(
                text,
                "\n# No tested run is recorded: `cargo xtask freeze --doctor <run>/doctor.json`\n\
                 # records the milestone conformance run, and `cargo xtask freeze --check`\n\
                 # fails until it is."
            );
            notes
                .push("no tested run is recorded (`freeze --check` fails until one is)".to_owned());
        }
    }
    Ok((text, notes))
}

/// `cargo xtask freeze --check`: the milestone gate. The file must be what
/// this tree generates, and it must record a tested run that validates
/// against this tree.
///
/// # Errors
/// Every problem found.
pub fn check(root: &Path) -> Result<Vec<&'static str>, Vec<String>> {
    let path = root.join(FREEZE_PATH);
    let existing = std::fs::read_to_string(&path)
        .map_err(|error| vec![format!("{}: {error}", path.display())])?;
    let tree = tree_part(root).map_err(|error| vec![error])?;
    let (recorded_tree, section) = match existing.split_once(TESTED_MARKER) {
        Some((before, after)) => (before.trim_end_matches('\n'), Some(after)),
        None => (existing.as_str(), None),
    };
    let mut problems = Vec::new();
    if !recorded_tree.starts_with(tree.trim_end_matches('\n')) {
        problems.push(
            "the freeze file is not what this tree generates: run `cargo xtask freeze` and \
             review the diff"
                .to_owned(),
        );
    }
    let Some(section) = section else {
        problems.push(format!(
            "no tested run is recorded ({TESTED_MARKER:?} is absent): record the milestone \
             conformance run with `cargo xtask freeze --doctor <run>/doctor.json`"
        ));
        return Err(problems);
    };
    let tested = toml::from_str::<toml::Value>(section)
        .map_err(|error| vec![format!("the tested run: {error}")])?;
    let Some(tested) = tested.get("tested") else {
        problems.push("the tested section has no [tested] table".to_owned());
        return Err(problems);
    };
    match validate_tested(root, &Tested::from_toml(tested)) {
        Ok(verified) if problems.is_empty() => Ok(verified),
        Ok(_) => Err(problems),
        Err(more) => {
            problems.extend(more);
            Err(problems)
        }
    }
}

/// `cargo xtask freeze`: write the freeze file for the tree at `root`.
///
/// # Errors
/// A value that cannot be read, or a file that cannot be written.
pub fn run(root: &Path, doctor: Option<&Path>) -> Result<PathBuf, String> {
    let doctor = match doctor {
        None => None,
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            Some(
                serde_json::from_str::<serde_json::Value>(&text)
                    .map_err(|error| format!("{}: {error}", path.display()))?,
            )
        }
    };
    let (text, notes) = generate(root, doctor.as_ref())?;
    for note in notes {
        eprintln!("xtask freeze: note: {note}");
    }
    let path = root.join(FREEZE_PATH);
    std::fs::write(&path, text).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn sha256_is_lowercase_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn const_lists_are_read_as_written() {
        let source = "pub const A: &[&str] = &[\n    \"/usr\",\n    \"/bin\", // a comment\n];\n\
                      pub const B: [&str; 2] = [\"x\", \"y\"];\n\
                      pub const C: &[&str] = &[];\n\
                      pub const D: &[&str] = &[OTHER];\n";
        assert_eq!(const_string_list(source, "A").unwrap(), ["/usr", "/bin"]);
        assert_eq!(const_string_list(source, "B").unwrap(), ["x", "y"]);
        assert!(const_string_list(source, "C").is_err(), "empty");
        assert!(const_string_list(source, "D").is_err(), "not a literal");
        assert!(const_string_list(source, "E").is_err(), "absent");
    }

    #[test]
    fn digests_are_read_in_table_order() {
        let table = "tool\ndigest: sha256:".to_owned()
            + &"a".repeat(64)
            + "\nmediation\ndigest: sha256:"
            + &"b".repeat(64)
            + "\nnarrowing filter digest: sha256:"
            + &"c".repeat(64)
            + "\ndigest: sha256:short\n";
        assert_eq!(
            nth_digest(&table, 0),
            Some(format!("sha256:{}", "a".repeat(64)))
        );
        assert_eq!(
            nth_digest(&table, 1),
            Some(format!("sha256:{}", "b".repeat(64)))
        );
        assert_eq!(
            nth_digest(&table, 2),
            Some(format!("sha256:{}", "c".repeat(64)))
        );
        assert_eq!(nth_digest(&table, 3), None);
    }

    #[test]
    fn the_tree_generates_a_parseable_freeze() {
        let (text, notes) = generate(&repo_root(), None).expect("the tree generates");
        let value: toml::Value = toml::from_str(&text).expect("TOML");
        assert_eq!(value["schema"].as_str(), Some(SCHEMA));
        let count = |key: &str| value.get(key).and_then(toml::Value::as_array).map(Vec::len);
        assert_eq!(count("launch_profile"), Some(3), "{text}");
        assert_eq!(count("baseline"), Some(4), "{text}");
        assert_eq!(count("manifest"), Some(4), "{text}");
        assert_eq!(count("backend_plan"), Some(3), "{text}");
        for profile in value["launch_profile"].as_array().unwrap() {
            let environment = profile["environment"].as_str().expect("an environment");
            serde_json::from_str::<serde_json::Value>(environment).expect("JSON");
        }
        // Without a recorded run, the absence is stated, never silent.
        if value.get("tested").is_none() {
            assert!(text.contains("No tested run is recorded"), "{text}");
            assert!(notes.iter().any(|note| note.contains("no tested run")));
        }
    }

    /// A minimal tree holding every build input, without `.git`.
    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a directory");
        let root = dir.path();
        std::fs::create_dir_all(root.join(build_provenance::INPUT_DIR)).unwrap();
        std::fs::write(
            root.join(build_provenance::INPUT_DIR).join("lib.rs"),
            "fn a() {}\n",
        )
        .unwrap();
        for file in build_provenance::INPUT_FILES {
            std::fs::create_dir_all(root.join(file).parent().unwrap()).unwrap();
            std::fs::write(root.join(file), format!("# {file}\n")).unwrap();
        }
        dir
    }

    fn clean(root: &Path) -> Tested {
        Tested {
            ready: Some(true),
            os: Some("linux".to_owned()),
            arch: Some("x86_64".to_owned()),
            target: Some("x86_64-unknown-linux-gnu".to_owned()),
            opt_level: Some("3".to_owned()),
            debug_assertions: Some(false),
            revision: Some("48a229ceaefd4985c50990b14116b6d856af0985".to_owned()),
            dirty: Some(false),
            inputs: Some(build_provenance::tree_digest(root).unwrap()),
            backend: true,
        }
    }

    /// Review F4: a tested run is the milestone run of this tree or nothing.
    #[test]
    fn a_tested_run_is_validated_strictly() {
        let dir = tree();
        let root = dir.path();
        assert_eq!(
            validate_tested(root, &clean(root)),
            Ok(vec!["inputs_match_tree"])
        );
        type Break = fn(&mut Tested);
        let cases: [(&str, Break); 12] = [
            ("not ready", |t| t.ready = Some(false)),
            ("ready unknown", |t| t.ready = None),
            ("aarch64", |t| t.arch = Some("aarch64".to_owned())),
            ("macOS", |t| t.os = Some("macos".to_owned())),
            ("an aarch64 target", |t| {
                t.target = Some("aarch64-unknown-linux-gnu".to_owned())
            }),
            ("unoptimised", |t| t.opt_level = Some("0".to_owned())),
            ("debug assertions", |t| t.debug_assertions = Some(true)),
            ("dirty", |t| t.dirty = Some(true)),
            ("dirty unknown", |t| t.dirty = None),
            ("an all-zero revision", |t| {
                t.revision = Some("0".repeat(40));
            }),
            ("no backend", |t| t.backend = false),
            ("other inputs", |t| {
                t.inputs = Some(format!("sha256:{}", "a".repeat(64)));
            }),
        ];
        for (label, change) in cases {
            let mut tested = clean(root);
            change(&mut tested);
            assert!(
                validate_tested(root, &tested).is_err(),
                "{label} was accepted"
            );
        }
        // A tree that changed after the run no longer validates.
        std::fs::write(
            root.join(build_provenance::INPUT_DIR).join("lib.rs"),
            "fn b() {}\n",
        )
        .unwrap();
        assert!(validate_tested(root, &clean_with(root, &clean_inputs_of(&tree()))).is_err());
    }

    fn clean_inputs_of(dir: &tempfile::TempDir) -> String {
        build_provenance::tree_digest(dir.path()).unwrap()
    }

    fn clean_with(root: &Path, inputs: &str) -> Tested {
        let mut tested = clean(root);
        tested.inputs = Some(inputs.to_owned());
        tested
    }

    fn git_in(root: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .expect("git runs");
        assert!(
            status.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&status.stderr)
        );
    }

    fn head(root: &Path) -> String {
        String::from_utf8(git(root, &["rev-parse", "HEAD"]).unwrap())
            .unwrap()
            .trim()
            .to_owned()
    }

    /// Where `.git` is present, the revision claim is checked against the
    /// commit itself, and frozen inputs may not have moved since it.
    #[test]
    fn with_git_the_revision_is_checked_against_its_own_tree() {
        let dir = tree();
        let root = dir.path();
        git_in(root, &["init", "-q"]);
        git_in(root, &["add", "-A"]);
        git_in(root, &["commit", "-q", "-m", "tested"]);
        let tested_revision = head(root);
        let mut tested = clean(root);
        tested.revision = Some(tested_revision.clone());
        assert_eq!(
            validate_tested(root, &tested),
            Ok(vec![
                "inputs_match_tree",
                "revision_is_ancestor_of_head",
                "inputs_match_revision",
                "frozen_inputs_unchanged_since_revision",
            ])
        );
        // A frozen input that is not a build input moves after the run.
        std::fs::create_dir_all(root.join("docs/specs/jail-v1/evidence")).unwrap();
        std::fs::write(root.join("docs/specs/jail-v1/evidence/table.txt"), "x").unwrap();
        git_in(root, &["add", "-A"]);
        git_in(root, &["commit", "-q", "-m", "evidence"]);
        let problems = validate_tested(root, &tested).unwrap_err();
        assert!(
            problems
                .iter()
                .any(|p| p.contains("a frozen input changed")),
            "{problems:?}"
        );
        // A revision whose own inputs are not the binary's: a false claim.
        std::fs::write(
            root.join(build_provenance::INPUT_DIR).join("lib.rs"),
            "fn c() {}\n",
        )
        .unwrap();
        git_in(root, &["add", "-A"]);
        git_in(root, &["commit", "-q", "-m", "other"]);
        let mut claimed = clean(root);
        claimed.revision = Some(tested_revision);
        let problems = validate_tested(root, &claimed).unwrap_err();
        assert!(
            problems
                .iter()
                .any(|p| p.contains("revision claim is false")),
            "{problems:?}"
        );
        // A revision that is not in HEAD's history.
        let mut foreign = clean(root);
        foreign.revision = Some("48a229ceaefd4985c50990b14116b6d856af0985".to_owned());
        assert!(validate_tested(root, &foreign).is_err());
    }

    /// Review F4: the whole host object is copied, and an unknown fact is
    /// named in `unknown`, never written as a value.
    #[test]
    fn a_tested_section_copies_the_host_and_names_what_was_unknown() {
        let dir = tree();
        let root = dir.path();
        let mut doctor: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                repo_root().join("docs/specs/jail-v1/examples/doctor-linux.json"),
            )
            .expect("the Linux doctor example"),
        )
        .expect("JSON");
        doctor["build"]["dirty"] = false.into();
        doctor["build"]["inputs"] = build_provenance::tree_digest(root).unwrap().into();
        doctor["host"]["linger"] = serde_json::Value::Null;
        doctor["host"]["sysctls"]["kernel.yama.ptrace_scope"] = serde_json::Value::Null;
        let section = tested_section(root, &doctor).expect("a clean run is recorded");
        let value: toml::Value = toml::from_str(&section).expect("TOML");
        let tested = &value["tested"];
        assert!(tested["host"].get("linger").is_none(), "{section}");
        assert!(
            tested["host"]["sysctls"]
                .get("kernel.yama.ptrace_scope")
                .is_none()
        );
        let unknown: Vec<&str> = tested["unknown"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap())
            .collect();
        assert!(unknown.contains(&"host.linger"), "{unknown:?}");
        assert!(
            unknown.contains(&"host.sysctls.kernel.yama.ptrace_scope"),
            "{unknown:?}"
        );
        // Every host fact the doctor had is there.
        for key in [
            "cgroup",
            "apparmor_userns_restriction",
            "memory",
            "virtualization",
        ] {
            assert!(tested["host"].get(key).is_some(), "{key}: {section}");
        }
        assert_eq!(
            tested["host"]["cgroup"]["subtree_control"]
                .as_array()
                .map(Vec::len),
            Some(3)
        );
        assert_eq!(tested["ready"].as_bool(), Some(true));
        assert_eq!(
            tested["backend"]["version"].as_str(),
            Some("bubblewrap 0.11.1")
        );
        // A run that is not ready, or not a doctor record, is refused.
        let mut unready = doctor.clone();
        unready["ready"] = false.into();
        assert!(tested_section(root, &unready).is_err());
        let mut other = doctor;
        other["schema"] = "ouro.jail.receipt/1".into();
        assert!(tested_section(root, &other).is_err());
    }
}
