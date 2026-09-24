//! Build provenance rules shared by `build.rs`, the `ouro-jail` binary and
//! `cargo xtask freeze` (jail-v1 §16; review F8: provenance is measured, not
//! asserted).
//!
//! Included by path (`#[path]`) from each of them, so there is one rule: it
//! uses only `std` and `sha2`, which all three already depend on.
//!
//! **The build environment contract.** The conformance driver copies the
//! tree without `.git`, so it names the revision in the environment of every
//! cargo invocation that builds or tests the jail, with the same values each
//! time (cargo tracks both variables, and a test step with different values
//! rebuilds the binary under the suite):
//!
//! - `OURO_BUILD_REVISION`: the full 40-hex commit being built; unset or
//!   empty means unknown. Anything else (abbreviated, not hex, all zeros)
//!   fails the build.
//! - `OURO_BUILD_DIRTY`: `true`/`1` or `false`/`0`; unset or empty means
//!   unknown. Set without a revision fails the build: a cleanliness claim
//!   about no named revision is a contradiction.
//!
//! **The measured part.** `inputs` is a digest of the files the binary is
//! built from, computed by `build.rs` from the tree cargo compiled:
//! SHA-256 over every file under `crates/ouro-jail/src` plus [`INPUT_FILES`],
//! sorted by their `/`-separated path relative to the repository root, each
//! as `path NUL u64-LE(length) bytes`, written `sha256:<hex>`. The same
//! digest computed from a commit's objects (`cargo xtask freeze`) shows
//! whether a binary's claimed revision is the tree it was built from.

use std::path::{Path, PathBuf};

use sha2::Digest as _;

/// The directory whose every file is a build input, relative to the
/// repository root.
pub const INPUT_DIR: &str = "crates/ouro-jail/src";

/// The other build inputs, relative to the repository root. Dependencies
/// are pinned by `Cargo.lock` (crates.io sources are immutable per version
/// and checksum), the compiler by `rust-toolchain.toml`.
pub const INPUT_FILES: [&str; 5] = [
    "crates/ouro-jail/build.rs",
    "crates/ouro-jail/Cargo.toml",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
];

/// A validated build environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// The 40-hex lowercase revision, when one was named.
    pub revision: Option<String>,
    /// Whether the named revision's tree had uncommitted changes.
    pub dirty: Option<bool>,
}

/// Validates `OURO_BUILD_REVISION` and `OURO_BUILD_DIRTY`.
///
/// # Errors
/// The rule the environment breaks.
pub fn validate(revision: Option<&str>, dirty: Option<&str>) -> Result<Claims, String> {
    let revision = revision.map(str::trim).filter(|value| !value.is_empty());
    let dirty = dirty.map(str::trim).filter(|value| !value.is_empty());
    let revision = match revision {
        None => None,
        Some(value)
            if value.len() == 40
                && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                && value.bytes().any(|byte| byte != b'0') =>
        {
            Some(value.to_ascii_lowercase())
        }
        Some(value) => {
            return Err(format!(
                "OURO_BUILD_REVISION must be a full 40-hex commit (not all zeros); got {value:?}"
            ));
        }
    };
    let dirty = match dirty {
        None => None,
        Some("true" | "1") => Some(true),
        Some("false" | "0") => Some(false),
        Some(value) => {
            return Err(format!(
                "OURO_BUILD_DIRTY must be true, false, 1 or 0; got {value:?}"
            ));
        }
    };
    if dirty.is_some() && revision.is_none() {
        return Err(
            "OURO_BUILD_DIRTY is set but OURO_BUILD_REVISION is not: a cleanliness claim \
             needs the revision it is about"
                .to_owned(),
        );
    }
    Ok(Claims { revision, dirty })
}

/// The build inputs under `root`, as `/`-separated relative paths, sorted.
///
/// # Errors
/// A directory or file that cannot be read.
pub fn input_files(root: &Path) -> std::io::Result<Vec<String>> {
    let mut files: Vec<String> = INPUT_FILES.iter().map(|file| (*file).to_owned()).collect();
    let mut stack: Vec<PathBuf> = vec![root.join(INPUT_DIR)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let meta = std::fs::metadata(&path)?;
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(std::io::Error::other)?
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                files.push(relative);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// The inputs digest over `(path, bytes)` pairs, which must be sorted by
/// path.
#[must_use]
pub fn digest<'a, I: IntoIterator<Item = (&'a str, &'a [u8])>>(files: I) -> String {
    let mut hasher = sha2::Sha256::new();
    for (path, bytes) in files {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// The inputs digest of the tree at `root`.
///
/// # Errors
/// A file that cannot be read.
pub fn tree_digest(root: &Path) -> std::io::Result<String> {
    let files = input_files(root)?;
    let mut contents = Vec::with_capacity(files.len());
    for file in &files {
        contents.push(std::fs::read(root.join(file))?);
    }
    Ok(digest(
        files
            .iter()
            .map(String::as_str)
            .zip(contents.iter().map(Vec::as_slice)),
    ))
}
