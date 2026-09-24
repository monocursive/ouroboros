//! Build provenance for `version --json` and `doctor --json` (jail-v1 §16:
//! "Freeze the Rust toolchain ... observer object/build provenance").
//!
//! Records, at compile time, the compiler that built this crate, the target
//! triple and the profile. The source revision is not read here: the
//! conformance driver copies the tree without `.git`, so it passes
//! `OURO_BUILD_REVISION` and `OURO_BUILD_DIRTY` in the environment and the
//! binary reads them with `option_env!`. Cargo tracks the variables
//! `option_env!` reads, so a change to either one rebuilds the crate without
//! a directive here (measured: removing one changed nothing).

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // `RUSTC` is the compiler cargo uses for this crate; `-V` is its own
    // version line, commit and date included. A compiler that cannot say
    // is recorded as unknown, never guessed from the toolchain file.
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(rustc)
        .arg("-V")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty() && !text.contains('\n'))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=OURO_BUILD_RUSTC={version}");

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=OURO_BUILD_TARGET={target}");

    // `PROFILE` is `release` or `debug`: the profile the build inherits from.
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=OURO_BUILD_PROFILE={profile}");
}
