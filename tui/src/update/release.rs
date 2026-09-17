//! The pinned-artifact primitives the updater already had, named so that fleet setup
//! can reuse them without reimplementing the download rules.
//!
//! The proposal is explicit that a missing-binary install reuses the updater's
//! HTTPS/size/checksum rules and resolves an *exact* version, never `latest`. So there
//! is one origin, one asset naming convention, one `SHA256SUMS` parser, and one set of
//! curl flags — this module just makes them callable from [`crate::fleet_setup`].

use std::sync::atomic::AtomicBool;

use anyhow::{bail, Context, Result};
use ring::digest::{Context as Digest, SHA256};

use super::transport::{self, Curl, BINARY_CAP, MANIFEST_CAP};
use super::REPOSITORY;

/// Harness-only origin override. See [`Origin::resolve`] for the whole of what it will
/// accept, which is a loopback HTTP or HTTPS server and nothing else.
pub const BASE_URL_ENV: &str = "OUROBOROS_RELEASE_BASE_URL";

/// Where release artifacts are fetched from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Origin {
    base: String,
    loopback_http: bool,
}

impl Origin {
    /// The official release download base.
    pub fn official() -> Self {
        Self {
            base: format!("{REPOSITORY}/releases/download"),
            loopback_http: false,
        }
    }

    /// The origin this process should use, honouring the harness override.
    ///
    /// The override exists for exactly one reason: an integration test cannot reach
    /// GitHub, and a missing-binary install that is never exercised end to end is a
    /// missing-binary install nobody has tested. It is deliberately narrow — a loopback
    /// host and nothing else, no path, no query, no credentials — so it cannot be turned
    /// into "fetch the product's binaries from somewhere else" in production. The
    /// checksum check is unchanged and still decides whether the bytes are installed.
    pub fn resolve() -> Result<Self> {
        match std::env::var(BASE_URL_ENV) {
            Err(_) => Ok(Self::official()),
            Ok(raw) => Self::loopback(&raw),
        }
    }

    pub fn loopback(raw: &str) -> Result<Self> {
        let trimmed = raw.trim().trim_end_matches('/');
        let (scheme, rest) = trimmed
            .split_once("://")
            .with_context(|| format!("{BASE_URL_ENV} must be an http or https URL"))?;
        if !matches!(scheme, "http" | "https") {
            bail!("{BASE_URL_ENV} must be an http or https URL");
        }
        if rest.contains('/') || rest.contains('?') || rest.contains('#') || rest.contains('@') {
            bail!("{BASE_URL_ENV} must be a bare origin: a host and an optional port, with no path, query or credentials");
        }
        // A bracketed IPv6 literal keeps its brackets; everything else stops at the port.
        let host = match rest.strip_prefix('[') {
            Some(inside) => match inside.split_once(']') {
                Some((literal, _)) => format!("[{literal}]"),
                None => bail!("{BASE_URL_ENV} has an unterminated IPv6 literal"),
            },
            None => rest.split(':').next().unwrap_or_default().to_string(),
        };
        let host = host.as_str();
        if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
            bail!(
                "{BASE_URL_ENV} may only name a loopback host (127.0.0.1, localhost or [::1]); it named `{host}`. Release artifacts are fetched from the official repository"
            );
        }
        Ok(Self {
            base: trimmed.to_string(),
            loopback_http: scheme == "http",
        })
    }

    pub fn is_official(&self) -> bool {
        *self == Self::official()
    }

    /// `<base>/v<version>/<name>`, the layout the release workflow publishes.
    pub fn url(&self, version: &str, name: &str) -> String {
        format!("{}/v{version}/{name}", self.base)
    }

    fn curl(&self) -> Curl {
        Curl {
            allow_http: self.loopback_http,
            ..Curl::default()
        }
    }
}

/// The asset name for one release and one target triple, as the workflow writes it.
pub fn asset_name(version: &str, target: &str) -> String {
    format!("ouro-{version}-{target}")
}

/// The target triple for a machine described by its `uname` and system version.
///
/// The same platform matrix the self-updater enforces — macOS 15+, glibc 2.39+, ARM64
/// or x86-64 — because "a Tailscale client works there" does not establish that an
/// Ouroboros release will run there.
pub fn target_triple(os: &str, arch: &str, system_version: &str) -> Result<String> {
    super::select_target(os, arch, system_version, false)
}

/// One release's `SHA256SUMS`, fetched and parsed.
pub fn checksums(origin: &Origin, version: &str, cancelled: &AtomicBool) -> Result<Vec<u8>> {
    let curl = origin.curl();
    let url = origin.url(version, "SHA256SUMS");
    let mut manifest = Vec::new();
    for attempt in 0..3 {
        manifest.clear();
        match curl.get(&url, false, &mut manifest, MANIFEST_CAP, cancelled) {
            Ok(()) => return Ok(manifest),
            Err(error) if attempt < 2 && transport::retryable(&error) => continue,
            Err(error) => return Err(error).context("downloading release checksums"),
        }
    }
    Ok(manifest)
}

/// The recorded sha256 for one asset in a manifest.
pub fn checksum_for(manifest: &[u8], asset: &str) -> Result<String> {
    super::checksum(manifest, asset)
}

/// Download one asset and refuse it unless its bytes hash to `expected`.
///
/// The bytes stay in memory: they are about to be streamed into an `ssh` stdin, and a
/// temporary file on the deployment host would be one more thing to clean up after a
/// crash. The cap is the updater's own.
pub fn fetch_verified(
    origin: &Origin,
    version: &str,
    asset: &str,
    expected: &str,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    let curl = origin.curl();
    let url = origin.url(version, asset);
    for attempt in 0..3 {
        let mut bytes = Vec::new();
        match curl.get(&url, false, &mut bytes, BINARY_CAP, cancelled) {
            Ok(()) => {
                let mut digest = Digest::new(&SHA256);
                digest.update(&bytes);
                let actual = super::hex(digest.finish().as_ref());
                if actual != expected {
                    bail!(
                        "the downloaded {asset} hashes to {actual}, and the release checksums say {expected}; nothing was sent to the target"
                    );
                }
                return Ok(bytes);
            }
            Err(error) if attempt < 2 && transport::retryable(&error) => continue,
            Err(error) => return Err(error).context("downloading a release executable"),
        }
    }
    bail!("the release executable could not be downloaded")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The override is a test harness's, and it cannot become a way to fetch the
    /// product's binaries from an arbitrary host.
    #[test]
    fn the_origin_override_accepts_only_a_bare_loopback_origin() {
        assert!(Origin::loopback("http://127.0.0.1:8080").is_ok());
        assert!(Origin::loopback("https://localhost:9443/").is_ok());
        assert!(Origin::loopback("http://[::1]:8080").is_ok());

        for hostile in [
            "http://evil.example",
            "https://github.com/monocursive/ouroboros/releases/download",
            "http://127.0.0.1:8080/path",
            "http://user@127.0.0.1:8080",
            "ftp://127.0.0.1",
            "127.0.0.1:8080",
            "http://127.0.0.1.evil.example",
        ] {
            assert!(
                Origin::loopback(hostile).is_err(),
                "{hostile} must not be accepted as a release origin"
            );
        }
    }

    /// An exact version, never `latest`, and the layout the workflow publishes.
    #[test]
    fn asset_urls_name_an_exact_version() {
        let origin = Origin::official();
        assert!(origin.is_official());
        assert_eq!(
            origin.url("0.1.8", "SHA256SUMS"),
            "https://github.com/monocursive/ouroboros/releases/download/v0.1.8/SHA256SUMS"
        );
        assert_eq!(
            asset_name("0.1.8", "aarch64-apple-darwin"),
            "ouro-0.1.8-aarch64-apple-darwin"
        );
        assert!(
            !origin.url("0.1.8", "x").contains("latest"),
            "a deployment resolves the exact operator release"
        );
    }

    /// The platform matrix is the updater's, so a target the release does not support is
    /// refused before anything is downloaded.
    #[test]
    fn the_target_triple_enforces_the_supported_matrix() {
        assert_eq!(
            target_triple("macos", "arm64", "15.1").expect("a supported mac"),
            "aarch64-apple-darwin"
        );
        assert_eq!(
            target_triple("linux", "x86_64", "glibc 2.39").expect("a supported linux"),
            "x86_64-unknown-linux-gnu"
        );
        assert!(target_triple("macos", "arm64", "14.6").is_err(), "macOS 14");
        assert!(
            target_triple("linux", "aarch64", "glibc 2.35").is_err(),
            "glibc 2.35"
        );
        assert!(target_triple("freebsd", "x86_64", "13").is_err());
        assert!(target_triple("linux", "riscv64", "glibc 2.39").is_err());
    }
}
