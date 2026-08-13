//! Bakes a release tarball into the binary when one is offered, and refuses to invent
//! one when it is not.
//!
//! `OUROBOROS_RELEASE_TARBALL` is the only way bytes get in. Without it the crate still
//! builds — attach and `--dev` need no release — so a cargo iteration never waits on
//! `mix release`. The `embed` feature compiles the extractor either way; the difference
//! is whether `embedded_release` names actual bytes.

fn main() {
    println!("cargo:rerun-if-env-changed=OUROBOROS_RELEASE_TARBALL");
    println!("cargo:rerun-if-env-changed=OUROBOROS_RELEASE_VERSION");
    println!("cargo:rustc-check-cfg=cfg(embedded_release)");

    #[cfg(feature = "embed")]
    embedded::bake();
}

#[cfg(feature = "embed")]
mod embedded {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};

    pub fn bake() {
        let Some(tarball) = env::var_os("OUROBOROS_RELEASE_TARBALL") else {
            return;
        };

        let tarball = PathBuf::from(tarball);

        if !tarball.is_absolute() {
            panic!(
                "OUROBOROS_RELEASE_TARBALL must be an absolute path; cargo does not run this \
                 script from a directory the caller chose, got: {}",
                tarball.display()
            );
        }

        println!("cargo:rerun-if-changed={}", tarball.display());

        let bytes = fs::read(&tarball).unwrap_or_else(|error| {
            panic!(
                "OUROBOROS_RELEASE_TARBALL={} is not readable: {error}",
                tarball.display()
            )
        });

        let version = release_version(&tarball);
        let digest = sha256_hex(&bytes);

        let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"))
            .join("embedded_release.rs");

        let source = format!(
            "pub const VERSION: &str = {version:?};\n\
             pub const SHA256: &str = {digest:?};\n\
             pub const TARBALL: &[u8] = include_bytes!({:?});\n",
            tarball
        );

        fs::write(&out, source).expect("the build script can write to OUT_DIR");

        println!("cargo:rustc-cfg=embedded_release");
    }

    /// The version an extracted release is filed under. A wrong guess would collide two
    /// different releases in one cache directory, so an unparseable name is a build
    /// failure rather than a default.
    fn release_version(tarball: &Path) -> String {
        if let Some(version) = env::var("OUROBOROS_RELEASE_VERSION")
            .ok()
            .filter(|version| !version.trim().is_empty())
        {
            return version.trim().to_string();
        }

        let name = tarball
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        let stem = name
            .strip_suffix(".tar.gz")
            .or_else(|| name.strip_suffix(".tgz"))
            .unwrap_or(name);

        match stem.rsplit_once('-') {
            Some((_prefix, version)) if !version.is_empty() => version.to_string(),
            _ => panic!(
                "cannot read a release version out of {name}; `mix release` names its tarball \
                 <release>-<version>.tar.gz. Set OUROBOROS_RELEASE_VERSION to name it explicitly"
            ),
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        let digest = Sha256::digest(bytes);
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
