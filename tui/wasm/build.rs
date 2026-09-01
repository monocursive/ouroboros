//! Reads the resolved `wasmtime` version out of the workspace lock so `doctor` can report the
//! runtime this binary is actually linked against.
//!
//! wasmtime exposes no version constant, and the alternative — printing the `"48"` requirement
//! written in `Cargo.toml` — would be a doctor reporting a pin as if it were a fact. Small, but
//! this helper's whole job is to be believed about what it can and cannot do. If the lock
//! cannot be read the version is reported as `unknown`, which is also true.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let lock = Path::new(&manifest).join("..").join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock.display());

    let version = std::fs::read_to_string(&lock)
        .ok()
        .and_then(|text| wasmtime_version(&text))
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=OURO_WASMTIME_VERSION={version}");
}

/// The `version` line of the `[[package]]` block whose name is exactly `wasmtime`. Exactly,
/// because `wasmtime-environ` and a dozen `wasmtime-internal-*` crates are in the same lock.
fn wasmtime_version(lock: &str) -> Option<String> {
    let mut found = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == r#"name = "wasmtime""# {
            found = true;
        } else if found {
            if let Some(rest) = line.strip_prefix("version = ") {
                return Some(rest.trim_matches('"').to_string());
            }
            if line.starts_with("[[") {
                found = false;
            }
        }
    }
    None
}
