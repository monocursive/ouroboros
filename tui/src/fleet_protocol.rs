//! What this binary can say about its own build without starting a BEAM.
//!
//! `docs/proposals/fleet-kiss.md` §12 replaced the hand-maintained
//! `@fleet_protocol_revision` with the pair `{ouroboros_version, otp_release}`, compared
//! exactly. So there is no number written twice here and no drift test: what is left is
//! the build metadata the version comparison reads.
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

/// The release-tree file `mix release` writes, relative to `releases/<vsn>/`.
pub const BUILD_METADATA_FILE: &str = "ouroboros-build.json";

/// What this binary can say about its own fleet compatibility without starting anything.
///
/// `otp_release` and `elixir_version` are `Option` on purpose: a build with no embedded
/// release genuinely does not know them, and the JSON form prints `null` rather than
/// inventing a version an operator might compare against a peer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BuildMetadata {
    pub ouroboros_version: String,
    pub otp_release: Option<String>,
    pub elixir_version: Option<String>,
    pub os: String,
    pub arch: String,
    /// Whether this binary carries a packaged runtime at all. `false` is a development
    /// build; the two version fields above are `null` in that case.
    pub embedded_release: bool,
    /// The Ouroboros version the embedded release recorded, which is a different fact
    /// from the one this client was compiled with.
    pub release_ouroboros_version: Option<String>,
}

/// The subset of `releases/<vsn>/ouroboros-build.json` this client reads.
///
/// Unknown fields are ignored and every field is optional, so a newer packaging step may
/// add keys without making an older client refuse the file it already understands.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct ReleaseBuild {
    #[serde(default)]
    pub ouroboros_version: Option<String>,
    #[serde(default)]
    pub otp_release: Option<String>,
    #[serde(default)]
    pub elixir_version: Option<String>,
}

/// This binary's fleet build metadata. Starts no runtime and touches no network.
pub fn build_metadata() -> BuildMetadata {
    metadata_from(embedded_build())
}

/// The shaping, separated from the lookup so every combination — no release, a release
/// that recorded nothing, a release that disagrees with this client — is a case a test
/// can drive rather than a case that needs a particular binary to exist.
fn metadata_from(release: Option<ReleaseBuild>) -> BuildMetadata {
    BuildMetadata {
        ouroboros_version: env!("CARGO_PKG_VERSION").to_string(),
        otp_release: release.as_ref().and_then(|build| build.otp_release.clone()),
        elixir_version: release
            .as_ref()
            .and_then(|build| build.elixir_version.clone()),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        embedded_release: release.is_some(),
        release_ouroboros_version: release
            .as_ref()
            .and_then(|build| build.ouroboros_version.clone()),
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
        let Ok(mut entry) = entry else { continue };
        // Only a regular file answers for the release. A link entry in a well-formed
        // archive carries no bytes of its own, so the scan below would move past it
        // anyway; this is the cheaper and more direct statement of the same rule, and
        // it holds for a reader that would otherwise follow a link's declared size.
        // No well-formed archive can distinguish the two guards, so no test does.
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let Ok(path) = entry.path().map(|path| path.into_owned()) else {
            continue;
        };
        if !is_build_metadata_path(&path) {
            continue;
        }
        let mut text = String::new();
        // `take` bounds the read; a larger file is read up to the cap and then fails to
        // parse. An entry that does not read or does not parse leaves the scan running:
        // a duplicate name earlier in the archive must not decide the answer for a
        // readable one after it.
        if entry
            .by_ref()
            .take(MAX_METADATA_BYTES)
            .read_to_string(&mut text)
            .is_err()
        {
            continue;
        }
        if let Ok(build) = serde_json::from_str(&text) {
            return Some(build);
        }
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

    /// The three states the packaging fact can be in, each one a different answer.
    #[test]
    fn an_absent_release_is_not_a_guess_and_a_present_one_names_its_own_version() {
        let none = metadata_from(None);
        assert!(!none.embedded_release);
        assert_eq!(none.otp_release, None);
        assert_eq!(none.elixir_version, None);
        assert_eq!(none.release_ouroboros_version, None);

        let packaged = metadata_from(Some(ReleaseBuild {
            ouroboros_version: Some("0.1.10".into()),
            otp_release: Some("29".into()),
            elixir_version: Some("1.20.2".into()),
        }));
        assert!(packaged.embedded_release);
        assert_eq!(packaged.otp_release.as_deref(), Some("29"));
        assert_eq!(
            packaged.release_ouroboros_version.as_deref(),
            Some("0.1.10")
        );

        // A release packaged before the metadata step: it exists, and says nothing.
        let silent = metadata_from(Some(ReleaseBuild::default()));
        assert!(silent.embedded_release);
        assert_eq!(silent.release_ouroboros_version, None);
    }

    /// The JSON form is a contract for scripts: the field names and the `null`s are the
    /// part an operator's `jq` depends on. §12 deleted `fleet_protocol_revision` from it.
    #[test]
    fn json_names_every_field_and_prints_unknown_versions_as_null() {
        let metadata = BuildMetadata {
            ouroboros_version: "0.1.10".into(),
            otp_release: None,
            elixir_version: None,
            os: "macos".into(),
            arch: "aarch64".into(),
            embedded_release: false,
            release_ouroboros_version: None,
        };
        let value = serde_json::to_value(&metadata).expect("build metadata serializes");
        assert_eq!(value["ouroboros_version"], "0.1.10");
        assert!(value["otp_release"].is_null());
        assert!(value["elixir_version"].is_null());
        assert_eq!(value["os"], "macos");
        assert_eq!(value["arch"], "aarch64");
        assert_eq!(value["embedded_release"], false);
        assert!(value["release_ouroboros_version"].is_null());
        assert!(
            value.get("fleet_protocol_revision").is_none(),
            "the revision is deleted, not nulled"
        );
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

        const METADATA: &str = r#"{"schema":2,
            "ouroboros_version":"0.1.8","otp_release":"28","elixir_version":"1.18.4"}"#;

        #[test]
        fn reads_the_metadata_file_out_of_a_release_tarball() {
            let bytes = tarball(&[
                ("bin/ouroboros", "#!/bin/sh\n"),
                ("releases/0.1.8/vm.args", "-name ouro\n"),
                ("releases/0.1.8/ouroboros-build.json", METADATA),
            ]);
            let build = read_release_build(&bytes).expect("the metadata file is found");
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
            assert_eq!(build.ouroboros_version, None);
        }

        /// A link cannot answer for the release, and a first entry that does not parse
        /// does not get to decide the answer for a readable one after it.
        #[test]
        fn a_shadowing_link_and_an_unreadable_duplicate_do_not_stop_the_scan() {
            let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::fast(),
            ));
            // A link entry in the release's own metadata path. In a well-formed archive
            // it carries no body of its own, so what keeps it from deciding the answer
            // is the scan continuing past an entry that yields nothing — the entry-type
            // check in `read_release_build` is a second guard over the same case, and
            // this archive cannot tell the two apart. What it does prove is the
            // property that matters: a link does not shadow the real file.
            let mut link = tar::Header::new_gnu();
            link.set_size(0);
            link.set_mode(0o777);
            link.set_entry_type(tar::EntryType::Symlink);
            builder
                .append_link(
                    &mut link,
                    "releases/0.1.8/ouroboros-build.json",
                    "/etc/passwd",
                )
                .expect("appending a symlink entry");
            let mut broken = tar::Header::new_gnu();
            let garbage = b"not json";
            broken.set_size(garbage.len() as u64);
            broken.set_mode(0o644);
            broken.set_cksum();
            builder
                .append_data(
                    &mut broken,
                    "releases/0.1.8/ouroboros-build.json",
                    &garbage[..],
                )
                .expect("appending an unreadable duplicate");
            let mut real = tar::Header::new_gnu();
            real.set_size(METADATA.len() as u64);
            real.set_mode(0o644);
            real.set_cksum();
            builder
                .append_data(
                    &mut real,
                    "releases/0.1.8/ouroboros-build.json",
                    METADATA.as_bytes(),
                )
                .expect("appending the real entry");
            let bytes = builder
                .into_inner()
                .expect("finishing the tar")
                .finish()
                .expect("finishing the gzip stream");

            let build = read_release_build(&bytes).expect("the readable entry answers");
            assert_eq!(
                build.otp_release.as_deref(),
                Some("28"),
                "a link and an unreadable duplicate both give way to the real entry"
            );
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
