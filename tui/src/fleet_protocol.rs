//! One fleet protocol revision, and the build metadata that answers for it.
//!
//! ## Why a constant and a drift test rather than a lookup
//!
//! [`Ouroboros.Cluster.runtime_compatible?/2`] compares the revision *exactly*: two
//! machines are compatible when their `{fleet_protocol_revision, ouroboros_version,
//! otp_release}` tuples are equal. The revision therefore has to be the same integer in
//! the runtime and in the client that reports on it, and the client cannot ask a runtime
//! for it — `ouro fleet protocol` is specified to answer without starting a BEAM, which
//! is the whole reason it is the command an onboarding preflight calls.
//!
//! So the number is written twice, and [`revision_matches_the_runtime`] parses
//! `lib/ouroboros/cluster.ex` and fails the build when the two copies disagree. Before
//! this module there were three numbers for one revision: the runtime's 5, a hardcoded 2
//! in `ouro fleet protocol`, and a 3 in `docs/FLEET.md`.
//!
//! ## Why OTP and Elixir come out of the release rather than out of this binary
//!
//! `ouro` is a Rust program. It links no BEAM, so nothing in it knows which ERTS its
//! embedded release carries, and asking the release would mean booting it. `mix release`
//! writes `releases/<vsn>/ouroboros-build.json` beside the boot scripts instead, and
//! [`build_metadata`] streams the embedded tarball far enough to read that one file.
//! A development build has no embedded release; it reports `null` for both versions and
//! `embedded_release: false`, because "unknown" is the honest answer and a guess here
//! would be a guess about cluster compatibility.

use serde::{Deserialize, Serialize};

/// The manual distributed-runtime compatibility fence, mirrored from
/// `@fleet_protocol_revision` in `lib/ouroboros/cluster.ex`.
pub const FLEET_PROTOCOL_REVISION: u32 = 5;

/// The release-tree file `mix release` writes, relative to `releases/<vsn>/`.
pub const BUILD_METADATA_FILE: &str = "ouroboros-build.json";

/// What this binary can say about its own fleet compatibility without starting anything.
///
/// `otp_release` and `elixir_version` are `Option` on purpose: a build with no embedded
/// release genuinely does not know them, and the JSON form prints `null` rather than
/// inventing a version an operator might compare against a peer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BuildMetadata {
    pub fleet_protocol_revision: u32,
    pub ouroboros_version: String,
    pub otp_release: Option<String>,
    pub elixir_version: Option<String>,
    pub os: String,
    pub arch: String,
    /// Whether this binary carries a packaged runtime at all. `false` is a development
    /// build; the two version fields above are `null` in that case.
    pub embedded_release: bool,
}

/// The subset of `releases/<vsn>/ouroboros-build.json` this client reads.
///
/// Unknown fields are ignored and every field is optional, so a newer packaging step may
/// add keys without making an older client refuse the file it already understands.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct ReleaseBuild {
    #[serde(default)]
    pub fleet_protocol_revision: Option<u32>,
    #[serde(default)]
    pub ouroboros_version: Option<String>,
    #[serde(default)]
    pub otp_release: Option<String>,
    #[serde(default)]
    pub elixir_version: Option<String>,
}

/// This binary's fleet build metadata. Starts no runtime and touches no network.
pub fn build_metadata() -> BuildMetadata {
    let release = embedded_build();
    BuildMetadata {
        fleet_protocol_revision: FLEET_PROTOCOL_REVISION,
        ouroboros_version: env!("CARGO_PKG_VERSION").to_string(),
        otp_release: release.as_ref().and_then(|build| build.otp_release.clone()),
        elixir_version: release
            .as_ref()
            .and_then(|build| build.elixir_version.clone()),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        embedded_release: release.is_some(),
    }
}

/// The metadata file inside the embedded release, when this binary has one.
///
/// A packaged binary whose release predates the packaging step returns
/// `Some(ReleaseBuild::default())`: the release exists, and its versions are unknown.
/// That distinction is what keeps `embedded_release` an honest fact about packaging
/// rather than a restatement of whether the metadata parsed.
#[cfg(feature = "embed")]
fn embedded_build() -> Option<ReleaseBuild> {
    let release = crate::runtime::embed::embedded()?;
    Some(read_release_build(release.bytes).unwrap_or_default())
}

#[cfg(not(feature = "embed"))]
fn embedded_build() -> Option<ReleaseBuild> {
    None
}

/// The largest metadata document this client will read out of a release tarball. The
/// file `mix release` writes is a few hundred bytes; the cap is what stops a malformed
/// or hostile archive from being read into memory as if it were one.
#[cfg(feature = "embed")]
const MAX_METADATA_BYTES: u64 = 64 * 1024;

/// Streams a `mix release` tarball far enough to read `releases/<vsn>/<BUILD_METADATA_FILE>`.
///
/// Nothing is unpacked and nothing is executed: the archive is decompressed through a
/// reader, entries are matched by path shape, and the first match is read under a cap.
#[cfg(feature = "embed")]
pub(crate) fn read_release_build(tarball: &[u8]) -> Option<ReleaseBuild> {
    use std::io::Read;

    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tarball));
    let entries = archive.entries().ok()?;
    for entry in entries {
        let mut entry = entry.ok()?;
        let path = entry.path().ok()?.into_owned();
        if !is_build_metadata_path(&path) {
            continue;
        }
        let mut text = String::new();
        // `take` bounds the read; a larger file is read up to the cap and then fails to
        // parse, which reports unknown versions rather than a truncated pair of them.
        entry
            .by_ref()
            .take(MAX_METADATA_BYTES)
            .read_to_string(&mut text)
            .ok()?;
        return serde_json::from_str(&text).ok();
    }
    None
}

/// `releases/<version>/ouroboros-build.json`, with or without the `./` prefix some tar
/// writers use. The shape is matched rather than a fixed string, because the version
/// directory is named by the release being built.
#[cfg(feature = "embed")]
fn is_build_metadata_path(path: &std::path::Path) -> bool {
    use std::path::Component;

    let components: Vec<_> = path
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect();
    let [Component::Normal(releases), Component::Normal(_version), Component::Normal(file)] =
        components.as_slice()
    else {
        return false;
    };
    *releases == "releases" && *file == BUILD_METADATA_FILE
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one place the Rust client and the Elixir runtime have to agree, held to it by
    /// a test rather than by a comment. `runtime_compatible?/2` compares the integer
    /// exactly, so a silent drift here is a fleet that refuses to form with no local
    /// evidence of why.
    #[test]
    fn revision_matches_the_runtime() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../lib/ouroboros/cluster.ex"
        ))
        .expect("lib/ouroboros/cluster.ex is readable from the crate directory");

        let literal = source
            .lines()
            .find_map(|line| line.trim().strip_prefix("@fleet_protocol_revision "))
            .expect("cluster.ex declares @fleet_protocol_revision")
            .trim()
            .parse::<u32>()
            .expect("@fleet_protocol_revision is an integer literal");

        assert_eq!(
            literal, FLEET_PROTOCOL_REVISION,
            "cluster.ex advertises fleet protocol {literal} and this client reports \
             {FLEET_PROTOCOL_REVISION}; bump tui/src/fleet_protocol.rs and docs/FLEET.md"
        );
    }

    /// A development build knows its own version and refuses to guess the runtime's.
    #[test]
    fn a_build_without_a_release_reports_unknown_versions() {
        let metadata = build_metadata();
        assert_eq!(metadata.fleet_protocol_revision, FLEET_PROTOCOL_REVISION);
        assert_eq!(metadata.ouroboros_version, env!("CARGO_PKG_VERSION"));
        assert!(!metadata.os.is_empty());
        assert!(!metadata.arch.is_empty());

        // `cargo test -p ouro` builds without `embed`, so there is never a release here.
        // The packaged case is covered by `scripts/release-smoke.py`.
        if !metadata.embedded_release {
            assert_eq!(metadata.otp_release, None);
            assert_eq!(metadata.elixir_version, None);
        }
    }

    /// The JSON form is a contract for scripts: the field names and the `null`s are the
    /// part an operator's `jq` depends on.
    #[test]
    fn json_names_every_field_and_prints_unknown_versions_as_null() {
        let metadata = BuildMetadata {
            fleet_protocol_revision: 5,
            ouroboros_version: "0.1.8".into(),
            otp_release: None,
            elixir_version: None,
            os: "macos".into(),
            arch: "aarch64".into(),
            embedded_release: false,
        };
        let value = serde_json::to_value(&metadata).expect("build metadata serializes");
        assert_eq!(value["fleet_protocol_revision"], 5);
        assert_eq!(value["ouroboros_version"], "0.1.8");
        assert!(value["otp_release"].is_null());
        assert!(value["elixir_version"].is_null());
        assert_eq!(value["os"], "macos");
        assert_eq!(value["arch"], "aarch64");
        assert_eq!(value["embedded_release"], false);
        assert_eq!(
            value.as_object().expect("an object").len(),
            7,
            "a new field is a change to a documented machine-readable shape"
        );
    }

    #[cfg(feature = "embed")]
    mod packaged {
        use super::*;
        use std::io::Write;

        /// Builds a gzipped tar the way `mix release` lays one out: boot material first,
        /// the metadata file inside `releases/<vsn>/`.
        fn tarball(entries: &[(&str, &str)]) -> Vec<u8> {
            let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::fast(),
            ));
            for (path, body) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, path, body.as_bytes())
                    .expect("appending a tar entry");
            }
            let encoder = builder.into_inner().expect("finishing the tar");
            let mut bytes = encoder.finish().expect("finishing the gzip stream");
            bytes.flush().expect("flushing");
            bytes
        }

        const METADATA: &str = r#"{"schema":1,"fleet_protocol_revision":5,
            "ouroboros_version":"0.1.8","otp_release":"28","elixir_version":"1.18.4"}"#;

        #[test]
        fn reads_the_metadata_file_out_of_a_release_tarball() {
            let bytes = tarball(&[
                ("bin/ouroboros", "#!/bin/sh\n"),
                ("releases/0.1.8/vm.args", "-name ouro\n"),
                ("releases/0.1.8/ouroboros-build.json", METADATA),
            ]);
            let build = read_release_build(&bytes).expect("the metadata file is found");
            assert_eq!(build.fleet_protocol_revision, Some(5));
            assert_eq!(build.ouroboros_version.as_deref(), Some("0.1.8"));
            assert_eq!(build.otp_release.as_deref(), Some("28"));
            assert_eq!(build.elixir_version.as_deref(), Some("1.18.4"));
        }

        /// `erl_tar` and friends write `./`-prefixed names; the same archive must read.
        #[test]
        fn a_dot_slash_prefixed_archive_reads_the_same() {
            let bytes = tarball(&[("./releases/0.1.8/ouroboros-build.json", METADATA)]);
            let build = read_release_build(&bytes).expect("the metadata file is found");
            assert_eq!(build.otp_release.as_deref(), Some("28"));
        }

        /// A release built before the packaging step, and a file planted somewhere else,
        /// both mean the same thing: this binary does not know the runtime's versions.
        #[test]
        fn a_release_without_the_metadata_file_reports_nothing() {
            assert_eq!(
                read_release_build(&tarball(&[("bin/ouroboros", "#!/bin/sh\n")])),
                None
            );
            assert_eq!(
                read_release_build(&tarball(&[(
                    "lib/ouroboros-0.1.8/ouroboros-build.json",
                    METADATA
                )])),
                None,
                "only the release's own metadata path answers for the release"
            );
        }

        /// Unknown keys are the expected case for an older client reading a newer
        /// release, and a missing key is `None` rather than a parse failure.
        #[test]
        fn added_and_missing_fields_are_both_tolerated() {
            let bytes = tarball(&[(
                "releases/0.1.8/ouroboros-build.json",
                r#"{"otp_release":"29","built_by":"some future step","schema":2}"#,
            )]);
            let build = read_release_build(&bytes).expect("the metadata file is found");
            assert_eq!(build.otp_release.as_deref(), Some("29"));
            assert_eq!(build.elixir_version, None);
            assert_eq!(build.fleet_protocol_revision, None);
        }

        /// An unreadable document reports unknown versions; it never panics and never
        /// half-reports one of a pair that must be compared together.
        #[test]
        fn an_unparseable_metadata_file_reports_nothing() {
            let bytes = tarball(&[("releases/0.1.8/ouroboros-build.json", "not json at all")]);
            assert_eq!(read_release_build(&bytes), None);

            let oversized = "x".repeat(MAX_METADATA_BYTES as usize + 4096);
            let bytes = tarball(&[("releases/0.1.8/ouroboros-build.json", &oversized)]);
            assert_eq!(read_release_build(&bytes), None);
        }
    }
}
