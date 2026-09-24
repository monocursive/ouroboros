//! `cargo xtask freeze`: the milestone-1 freeze file (jail-v1 §16).
//!
//! §16: "Freeze the Rust toolchain, Cargo.lock, backend version/hashes,
//! filter digest, observer object/build provenance and tested host manifest
//! with the milestone report. Re-run relevant conformance when any of these
//! change. A dependency update must not silently broaden mounted files or
//! allow-hosts."
//!
//! This writes `docs/specs/jail-v1/milestone-1-freeze.toml` from the tree
//! itself: the pinned toolchain, the lock file's hash, the filter and
//! closed-set digests from the checked-in evidence tables, the contained
//! mount baselines, the bundled launch profiles' mounts and allowed hosts,
//! and the frozen schemas (J5-C's `frozen-schemas.toml`, when it exists).
//! With `--doctor`, it also records the tested run: the `doctor --json` a
//! conformance run wrote, which names the build, the binaries and the host.
//! `crates/ouro-jail/tests/portable_freeze.rs` fails when an in-tree value
//! drifts from the file, so a change to any of them is a visible decision to
//! re-run conformance and regenerate, never a silent one.
//!
//! Every value comes from a file, never from this program's own opinion, so
//! the generator needs no dependency on the jail; the test checks the file
//! against the jail's own constants and digests.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Where the freeze file lives, relative to the repository root.
pub const FREEZE_PATH: &str = "docs/specs/jail-v1/milestone-1-freeze.toml";
/// The freeze file's own identifier.
pub const SCHEMA: &str = "ouro.jail.milestone-freeze/1";

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

/// The freeze file's text for the tree at `root`, with the tested run from
/// `doctor` (a conformance run's `doctor --json`) when one is given.
///
/// # Errors
/// Any value that cannot be read or is not what the freeze expects.
pub fn generate(root: &Path, doctor: Option<&serde_json::Value>) -> Result<String, String> {
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

    // The tested run.
    if let Some(doctor) = doctor {
        tested(w, doctor)?;
    } else {
        let _ = writeln!(
            w,
            "\n# No tested run recorded: pass `--doctor <run>/doctor.json` from the\n\
             # milestone conformance run to record its build, binaries and host."
        );
    }
    Ok(out)
}

/// The `[tested]` section, from a conformance run's `doctor --json`.
fn tested(w: &mut String, doctor: &serde_json::Value) -> Result<(), String> {
    if doctor["schema"] != "ouro.jail.doctor/1" {
        return Err("the --doctor file is not an ouro.jail.doctor/1 record".to_owned());
    }
    let text = |value: &serde_json::Value, what: &str| -> Result<String, String> {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("the --doctor record has no {what}"))
    };
    let revision = text(&doctor["build"]["revision"], "build.revision")?;
    if doctor["build"]["dirty"] != serde_json::Value::Bool(false) {
        return Err(
            "the --doctor record's build is not a clean tree (build.dirty is not false)".to_owned(),
        );
    }
    let _ = writeln!(
        w,
        "\n# The tested run: the conformance run's `doctor --json` (§3.2 host manifest).\n\
         # Not an in-tree value; recorded so the milestone report names what was tested."
    );
    let _ = writeln!(w, "[tested]");
    let _ = writeln!(w, "revision = {}", quote(&revision));
    for (key, path) in [
        ("rustc", &doctor["build"]["rustc"]),
        ("target", &doctor["build"]["target"]),
        ("profile", &doctor["build"]["profile"]),
        ("platform_os", &doctor["platform"]["os"]),
        ("platform_arch", &doctor["platform"]["arch"]),
        (
            "ouro_jail_sha256",
            &doctor["binaries"]["ouro-jail"]["sha256"],
        ),
    ] {
        let _ = writeln!(w, "{key} = {}", quote(&text(path, key)?));
    }
    let bwrap = &doctor["binaries"]["bwrap"];
    if bwrap.is_null() {
        return Err("the --doctor record resolved no bubblewrap".to_owned());
    }
    let _ = writeln!(w, "[tested.backend]");
    for key in ["path", "version", "sha256"] {
        let _ = writeln!(
            w,
            "{key} = {}",
            quote(&text(&bwrap[key], &format!("bwrap.{key}"))?)
        );
    }
    let host = &doctor["host"];
    let _ = writeln!(w, "[tested.host]");
    for key in [
        "kernel_release",
        "kernel_version",
        "distribution",
        "operator_identity",
    ] {
        let _ = writeln!(
            w,
            "{key} = {}",
            quote(&text(&host[key], &format!("host.{key}"))?)
        );
    }
    let _ = writeln!(w, "linger = {}", host["linger"].as_bool().unwrap_or(false));
    let _ = writeln!(w, "[tested.host.sysctls]");
    if let Some(sysctls) = host["sysctls"].as_object() {
        for (name, value) in sysctls {
            if let Some(value) = value.as_str() {
                let _ = writeln!(w, "{} = {}", quote(name), quote(value));
            }
        }
    }
    Ok(())
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
    let text = generate(root, doctor.as_ref())?;
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
        let text = generate(&repo_root(), None).expect("the tree generates");
        let value: toml::Value = toml::from_str(&text).expect("TOML");
        assert_eq!(value["schema"].as_str(), Some(SCHEMA));
        assert!(value.get("tested").is_none());
        assert_eq!(
            value["launch_profile"].as_array().map(Vec::len),
            Some(3),
            "{text}"
        );
    }

    #[test]
    fn a_tested_run_must_be_a_clean_doctor_record() {
        let example: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                repo_root().join("docs/specs/jail-v1/examples/doctor-linux.json"),
            )
            .expect("the Linux doctor example"),
        )
        .expect("JSON");
        let mut clean = example.clone();
        clean["build"]["dirty"] = serde_json::Value::Bool(false);
        let text = generate(&repo_root(), Some(&clean)).expect("a clean record is recorded");
        let value: toml::Value = toml::from_str(&text).expect("TOML");
        assert_eq!(
            value["tested"]["backend"]["version"].as_str(),
            Some("bubblewrap 0.11.1")
        );
        // A dirty tree, an unknown revision or a record that is not a
        // doctor report is refused: the freeze never names a build nobody
        // can reproduce.
        let mut dirty = clean.clone();
        dirty["build"]["dirty"] = serde_json::Value::Bool(true);
        assert!(generate(&repo_root(), Some(&dirty)).is_err());
        let mut unknown = clean.clone();
        unknown["build"]["revision"] = serde_json::Value::Null;
        assert!(generate(&repo_root(), Some(&unknown)).is_err());
        let mut other = clean;
        other["schema"] = "ouro.jail.receipt/1".into();
        assert!(generate(&repo_root(), Some(&other)).is_err());
    }
}
