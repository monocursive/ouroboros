//! Reads the resolved `wasmtime` version out of the workspace lock, and the target triple out
//! of cargo's own environment, so `doctor` can report the runtime this binary is actually
//! linked against and the machine it was built for.
//!
//! wasmtime exposes no version constant, and the alternative — printing the `"48"` requirement
//! written in `Cargo.toml` — would be a doctor reporting a pin as if it were a fact. Small, but
//! this helper's whole job is to be believed about what it can and cannot do. If the lock
//! cannot be read the version is reported as `unknown`, which is also true.
//!
//! The triple matters for the same reason as of W8: a precompiled component is machine code for
//! one triple built by one wasmtime, and a node admits one only when both of its own readings
//! match the manifest exactly. `TARGET` is what cargo compiled this binary for, which is the
//! only honest source for it — `std::env::consts` would report the pair the *host* runs, which
//! is a different question on a cross-build.

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

    // Set by cargo for every build; `unknown` only if that ever stops being true.
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=OURO_TARGET={target}");
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
