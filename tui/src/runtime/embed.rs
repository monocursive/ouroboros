//! The embedded release: verify, extract once, and keep the cache small.
//!
//! ## The digest is checked before anything is unpacked
//!
//! The bytes are the binary's own, so this is an integrity check rather than a trust
//! decision — a truncated download or a corrupted page should fail as a refusal to
//! extract, not as a release that half exists. Nothing is unpacked until the digest
//! matches what the build recorded.
//!
//! ## Extraction is atomic, and losing the race is not an error
//!
//! Cold runs coordinate repair and publication with a bounded private extraction lock.
//! Each extraction unpacks into a `.tmp-<pid>-<n>` sibling and renames it into place.
//! If publication nevertheless loses a rename race, the caller deletes its own temporary
//! copy and validates the completed winner before using it. A half-written release is
//! never reachable under its real name.
//!
//! ## Reuse is a lookup, and the cache repairs itself
//!
//! A directory whose name carries the full recorded digest is reused without hashing the
//! payload again, but it must be release-shaped — `bin/` and `releases/` present — and
//! carry the completion marker for that exact digest and version. The marker is written
//! inside the temporary directory and published atomically with the release. An incomplete
//! or mismatched entry is checked again under the extraction lock, removed and extracted
//! again. This is an extraction identity
//! check, not detection of later payload tampering. The releases directory itself is
//! kept private to its owner, matching every other directory this crate creates.
//!
//! ## A start is a use, and collection counts uses
//!
//! The cache is keyed by the digest, so recognising an already-extracted release costs a
//! directory lookup rather than a pass over the whole embedded payload — on a warm start,
//! the difference between faulting in every embedded byte and faulting in none of them.
//! Reuse restamps the directory, so [`gc`] keeps the two most recently
//! *started* releases rather than the two most recently unpacked ones: a daemon running
//! out of a release nobody has replaced twice is not something a later start collects.

use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};

#[cfg(embedded_release)]
mod baked {
    include!(concat!(env!("OUT_DIR"), "/embedded_release.rs"));
}

static TEMPORARY: AtomicU32 = AtomicU32::new(0);
const COMPLETION_MARKER: &str = ".ouroboros-release-complete";
const EXTRACTION_LOCK: &str = ".extract.lock";

/// How many extracted releases survive a collection. Two, so that the release a running
/// daemon was started from outlives the one that replaced it.
pub const KEEP: usize = 2;

/// A release baked into this binary at build time.
#[derive(Debug, Clone, Copy)]
pub struct Release {
    pub version: &'static str,
    pub sha256: &'static str,
    pub bytes: &'static [u8],
}

/// The embedded release, when this binary was built with one.
pub fn embedded() -> Option<Release> {
    #[cfg(embedded_release)]
    {
        Some(Release {
            version: baked::VERSION,
            sha256: baked::SHA256,
            bytes: baked::TARBALL,
        })
    }

    #[cfg(not(embedded_release))]
    {
        None
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What a release is filed under: its version and complete artifact digest. Builds of
/// the same version must remain distinct even when their digest prefixes collide.
pub fn directory_name(version: &str, sha256: &str) -> String {
    format!("{version}+{sha256}")
}

/// Extracts the embedded release, verifying it first.
pub fn extract_embedded(release: &Release, releases_dir: &Path) -> Result<PathBuf> {
    extract(release.bytes, release.sha256, release.version, releases_dir)
}

/// Verifies and unpacks a release tarball, returning the directory it now lives in.
pub fn extract(
    bytes: &[u8],
    expected_sha256: &str,
    version: &str,
    releases_dir: &Path,
) -> Result<PathBuf> {
    // Warm reuse checks the published extraction identity without faulting the embedded
    // payload into memory. It does not revalidate every cached payload file.
    let expected = expected_sha256.to_ascii_lowercase();
    let destination = releases_dir.join(directory_name(version, &expected));

    if cache_matches(&destination, version, &expected) {
        touch(&destination);
        return Ok(destination);
    }

    extract_uncached(bytes, &expected, version, releases_dir)
}

fn extract_uncached(
    bytes: &[u8],
    expected: &str,
    version: &str,
    releases_dir: &Path,
) -> Result<PathBuf> {
    prepare_releases_dir(releases_dir)?;
    let _lock = lock_extraction(releases_dir, Duration::from_secs(30))?;
    let destination = releases_dir.join(directory_name(version, expected));

    // Another extractor may have repaired this entry after our initial observation.
    // Recheck while holding the same lock used through invalidation and publication;
    // a delayed observer must never delete a newly completed extraction.
    if cache_matches(&destination, version, expected) {
        touch(&destination);
        return Ok(destination);
    }

    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if metadata.is_dir() {
                fs::remove_dir_all(&destination)
            } else {
                fs::remove_file(&destination)
            }
            .with_context(|| format!("removing incomplete cache {}", destination.display()))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspecting the release cache entry"),
    }

    let actual = sha256_hex(bytes);

    if actual != expected {
        bail!(
            "the embedded release does not match the digest recorded at build time \
             (expected {expected}, got {actual}); refusing to extract it"
        );
    }

    let temporary = releases_dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        TEMPORARY.fetch_add(1, Ordering::Relaxed)
    ));

    // A leftover from a killed extraction is this process's to clear: the name carries
    // its own pid, so nothing else can be using it.
    let _ = fs::remove_dir_all(&temporary);
    fs::create_dir_all(&temporary)?;

    let unpacked = unpack(bytes, &temporary)
        .and_then(|()| make_executable(&temporary))
        .and_then(|()| write_completion(&temporary, version, expected));

    if let Err(error) = unpacked {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }

    publish_completed(&temporary, &destination, version, expected)?;
    Ok(destination)
}

fn lock_extraction(releases_dir: &Path, timeout: Duration) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(releases_dir.join(EXTRACTION_LOCK))
        .context("opening the release extraction lock")?;
    // Keep this inode permanently: unlinking it would let a waiter and a new caller
    // lock different files. Closing this owned descriptor releases the advisory lock.
    let started = Instant::now();
    loop {
        // SAFETY: flock acts on this live owned descriptor and has no pointer arguments.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock && error.kind() != io::ErrorKind::Interrupted {
            return Err(error).context("locking release extraction");
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            bail!("timed out waiting for release extraction to finish; retry when the other launch completes");
        }
        std::thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}

fn publish_completed(
    temporary: &Path,
    destination: &Path,
    version: &str,
    digest: &str,
) -> Result<()> {
    match fs::rename(temporary, destination) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_dir_all(temporary);

            if cache_matches(destination, version, digest) {
                // Only a completed extraction of the exact same artifact is a winner.
                touch(destination);
                return Ok(());
            }

            Err(error).with_context(|| format!("publishing {}", destination.display()))
        }
    }
}

fn unpack(bytes: &[u8], destination: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(GzDecoder::new(io::Cursor::new(bytes)));
    archive.set_overwrite(true);

    // `unpack` refuses entries whose paths escape the destination, which is the property
    // that makes extracting an archive into a cache directory safe at all.
    archive
        .unpack(destination)
        .with_context(|| format!("unpacking the release into {}", destination.display()))
}

fn release_shaped(release: &Path) -> bool {
    [
        release.to_path_buf(),
        release.join("bin"),
        release.join("releases"),
    ]
    .iter()
    .all(|path| fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir()))
}

fn completion_identity(version: &str, digest: &str) -> String {
    format!("ouroboros-release-cache-v1\n{digest}\n{version}")
}

fn cache_matches(release: &Path, version: &str, digest: &str) -> bool {
    if !release_shaped(release) {
        return false;
    }

    let marker = release.join(COMPLETION_MARKER);
    let expected = completion_identity(version, digest);
    let Ok(metadata) = fs::symlink_metadata(&marker) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() != expected.len() as u64 {
        return false;
    }
    let Ok(file) = fs::File::open(marker) else {
        return false;
    };
    let mut actual = Vec::new();
    file.take(expected.len() as u64 + 1)
        .read_to_end(&mut actual)
        .is_ok()
        && actual == expected.as_bytes()
}

fn write_completion(release: &Path, version: &str, digest: &str) -> Result<()> {
    if !release_shaped(release) {
        bail!("the embedded archive has no complete release shape; refusing to publish it");
    }

    // Reserve this filename to the extractor. In particular, never follow a marker
    // symlink supplied by an archive. The directory rename publishes marker and payload
    // together only after extraction and executable repair have finished.
    let mut marker = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(release.join(COMPLETION_MARKER))
        .context("creating the release completion marker")?;
    marker.write_all(completion_identity(version, digest).as_bytes())?;
    marker
        .sync_all()
        .context("syncing the release completion marker")
}

fn prepare_releases_dir(releases_dir: &Path) -> Result<()> {
    fs::create_dir_all(releases_dir)
        .with_context(|| format!("creating {}", releases_dir.display()))?;

    let metadata = fs::metadata(releases_dir)
        .with_context(|| format!("reading {}", releases_dir.display()))?;

    let mut permissions = metadata.permissions();
    let mode = permissions.mode();

    if mode & 0o077 != 0 {
        permissions.set_mode(mode & !0o077);
        fs::set_permissions(releases_dir, permissions)
            .with_context(|| format!("restricting {}", releases_dir.display()))?;
    }

    Ok(())
}

/// Restamps a release as used. Failure costs a suboptimal collection order and nothing
/// else, so it is not worth failing a start over.
fn touch(path: &Path) {
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return;
    };

    // SAFETY: the pointer is valid for the call, and a null `times` is the documented way
    // to ask for "now".
    unsafe {
        libc::utimes(path.as_ptr(), std::ptr::null());
    }
}

/// Restores the executable bit on everything a release is started through. A tarball
/// built elsewhere may carry modes this filesystem did not keep.
///
/// The scripts under `releases/<version>/` are named rather than swept: `bin/<release>`
/// execs `releases/<version>/elixir`, but that directory also holds `sys.config`,
/// `vm.args`, and the boot scripts, and marking configuration executable is not a mode
/// this pass has any reason to hand out.
fn make_executable(root: &Path) -> Result<()> {
    let mut directories = vec![root.join("bin")];

    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();

            if name.to_string_lossy().starts_with("erts-") {
                directories.push(entry.path().join("bin"));
            }
        }
    }

    for directory in directories {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_file() {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                    .with_context(|| format!("making {} executable", path.display()))?;
            }
        }
    }

    if let Ok(entries) = fs::read_dir(root.join("releases")) {
        for entry in entries.flatten() {
            for script in ["elixir", "iex"] {
                let path = entry.path().join(script);

                if path.is_file() {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                        .with_context(|| format!("making {} executable", path.display()))?;
                }
            }
        }
    }

    Ok(())
}

/// Keeps the newest `keep` releases and removes the rest, newest by modification time.
/// Temporary directories from a killed extraction are collected too.
pub fn gc(releases_dir: &Path, keep: usize) -> Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(releases_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context(format!("reading {}", releases_dir.display())),
    };

    let mut releases: Vec<(SystemTime, PathBuf)> = Vec::new();
    let mut removed = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();

        if !path.is_dir() {
            continue;
        }

        let name = entry.file_name();
        let name = name.to_string_lossy();

        if name.starts_with(".tmp-") {
            let pid = name
                .split('-')
                .nth(1)
                .and_then(|pid| pid.parse::<i32>().ok())
                .unwrap_or(0);

            // Another process may still be unpacking into its own temporary directory.
            if !super::pid_alive(pid) {
                fs::remove_dir_all(&path)?;
                removed.push(path);
            }

            continue;
        }

        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        releases.push((modified, path));
    }

    releases.sort_by_key(|(modified, _path)| std::cmp::Reverse(*modified));

    for (_modified, path) in releases.into_iter().skip(keep) {
        fs::remove_dir_all(&path)?;
        removed.push(path);
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    static SCRATCH: AtomicU32 = AtomicU32::new(0);

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ouro-embed-{name}-{}-{}",
            std::process::id(),
            SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));

        fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    /// A release-shaped tarball: a launcher under `bin/` and one file beside it. Small
    /// enough to build in a test, shaped enough to exercise the executable-bit pass.
    fn fixture_tarball() -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);

        let launcher_bytes = b"#!/bin/sh\necho started\n";
        let mut launcher = tar::Header::new_gnu();
        launcher.set_size(launcher_bytes.len() as u64);
        launcher.set_mode(0o644);
        launcher.set_cksum();
        builder
            .append_data(&mut launcher, "bin/ouroboros", &launcher_bytes[..])
            .expect("appending the launcher");

        let mut version = tar::Header::new_gnu();
        version.set_size(6);
        version.set_mode(0o644);
        version.set_cksum();
        builder
            .append_data(&mut version, "releases/start_erl.data", &b"1.2.3\n"[..])
            .expect("appending a release file");

        // `bin/<release> start` execs this one, and it arrives unexecutable here on
        // purpose: a tarball whose modes did not survive the trip is the case the
        // executable-bit pass exists for.
        let mut elixir = tar::Header::new_gnu();
        elixir.set_size(21);
        elixir.set_mode(0o644);
        elixir.set_cksum();
        builder
            .append_data(
                &mut elixir,
                "releases/1.2.3/elixir",
                &b"#!/bin/sh\nexec erl\n\n\n"[..],
            )
            .expect("appending the boot script");

        let mut config = tar::Header::new_gnu();
        config.set_size(4);
        config.set_mode(0o644);
        config.set_cksum();
        builder
            .append_data(&mut config, "releases/1.2.3/sys.config", &b"[].\n"[..])
            .expect("appending release configuration");

        let encoder = builder.into_inner().expect("finishing the archive");
        encoder.finish().expect("flushing the archive")
    }

    /// A tarball whose only member would write outside the unpack destination.
    /// `set_path` refuses that name, so the header is filled the way a hostile
    /// archive would be.
    fn escaping_tarball() -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);

        const PAYLOAD: &[u8] = b"pwned\n";
        let mut header = tar::Header::new_gnu();
        {
            let gnu = header.as_gnu_mut().expect("a GNU header");
            for (slot, byte) in gnu.name.iter_mut().zip(b"../pwned") {
                *slot = *byte;
            }
        }
        header.set_size(PAYLOAD.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append(&header, PAYLOAD)
            .expect("appending an escaping member");

        let encoder = builder.into_inner().expect("finishing the archive");
        encoder.finish().expect("flushing the archive")
    }

    #[test]
    fn extracts_verifies_and_marks_the_launcher_executable() {
        let dir = scratch("extract");
        let bytes = fixture_tarball();
        let digest = sha256_hex(&bytes);

        let release = extract(&bytes, &digest, "9.9.9", &dir).expect("an extracted release");

        assert_eq!(
            release.file_name().unwrap().to_string_lossy(),
            format!("9.9.9+{digest}")
        );
        assert!(cache_matches(&release, "9.9.9", &digest));

        let launcher = release.join("bin").join("ouroboros");
        assert!(launcher.is_file());

        let mode = fs::metadata(&launcher).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "a launcher that is not executable cannot start"
        );

        assert!(release.join("releases").join("start_erl.data").is_file());

        // The script `bin/<release> start` execs lives outside every directory the
        // wholesale pass walks, and arrived unexecutable.
        let boot = release.join("releases").join("1.2.3").join("elixir");
        let mode = fs::metadata(&boot).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "the release launcher execs this script by path"
        );

        let config = release.join("releases").join("1.2.3").join("sys.config");
        let mode = fs::metadata(&config).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "configuration is not something to make executable"
        );

        // A second extraction of the same bytes is a lookup, not a re-unpack.
        let again = extract(&bytes, &digest, "9.9.9", &dir).expect("the same release");
        assert_eq!(again, release);

        fs::remove_dir_all(&dir).ok();
    }

    /// The lookup that skips re-hashing is keyed by the *recorded* digest, so bytes that
    /// were never verified must not be able to reach it.
    #[test]
    fn a_present_release_is_reused_without_rehashing_the_payload() {
        let dir = scratch("reuse");
        let bytes = fixture_tarball();
        let digest = sha256_hex(&bytes);

        let release = extract(&bytes, &digest, "9.9.9", &dir).expect("an extracted release");

        // Uppercase names the same digest, and must name the same directory.
        let again = extract(&[], &digest.to_ascii_uppercase(), "9.9.9", &dir)
            .expect("a release already on disk");

        assert_eq!(again, release);

        // Nothing on disk yet under this digest, so the bytes are hashed and refused.
        let error = extract(&[], &digest, "8.8.8", &dir).expect_err("a refusal");
        assert!(
            error.to_string().contains("does not match the digest"),
            "unexpected error: {error}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_shared_digest_prefix_cannot_reuse_another_artifact() {
        let dir = scratch("digest-prefix");
        let bytes = fixture_tarball();
        let digest = sha256_hex(&bytes);
        let release = extract(&bytes, &digest, "9.9.9", &dir).unwrap();
        let mut other = digest.clone();
        other.pop();
        other.push(if digest.ends_with('0') { '1' } else { '0' });
        assert_eq!(&digest[..8], &other[..8]);
        assert_ne!(
            directory_name("9.9.9", &digest),
            directory_name("9.9.9", &other)
        );

        let error = extract(&[], &other, "9.9.9", &dir)
            .expect_err("a different full digest must verify its own artifact");
        assert!(error.to_string().contains("does not match the digest"));
        assert!(cache_matches(&release, "9.9.9", &digest));
        assert!(!dir.join(directory_name("9.9.9", &other)).exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_or_mismatched_completion_markers_force_verified_extraction() {
        for damage in ["missing", "digest", "version", "trailing", "symlink"] {
            let dir = scratch(damage);
            let bytes = fixture_tarball();
            let digest = sha256_hex(&bytes);
            let release = extract(&bytes, &digest, "9.9.9", &dir).unwrap();
            let marker = release.join(COMPLETION_MARKER);
            match damage {
                "missing" => fs::remove_file(&marker).unwrap(),
                "digest" => {
                    fs::write(&marker, completion_identity("9.9.9", &"0".repeat(64))).unwrap()
                }
                "version" => fs::write(&marker, completion_identity("8.8.8", &digest)).unwrap(),
                "trailing" => fs::write(
                    &marker,
                    format!("{}x", completion_identity("9.9.9", &digest)),
                )
                .unwrap(),
                "symlink" => {
                    let outside = dir.join("marker-target");
                    fs::rename(&marker, &outside).unwrap();
                    std::os::unix::fs::symlink(&outside, &marker).unwrap();
                }
                _ => unreachable!(),
            }
            fs::write(release.join("stale-cache"), b"must be replaced").unwrap();

            let repaired = extract(&bytes, &digest, "9.9.9", &dir).unwrap();
            assert_eq!(repaired, release);
            assert!(cache_matches(&repaired, "9.9.9", &digest), "{damage}");
            assert!(!repaired.join("stale-cache").exists(), "{damage}");
            assert_eq!(
                fs::read(repaired.join("bin/ouroboros")).unwrap(),
                b"#!/bin/sh\necho started\n"
            );
            fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn a_completion_marker_cannot_hide_a_missing_release_directory() {
        let dir = scratch("incomplete-marked");
        let bytes = fixture_tarball();
        let digest = sha256_hex(&bytes);
        let release = extract(&bytes, &digest, "9.9.9", &dir).unwrap();
        fs::remove_dir_all(release.join("bin")).unwrap();

        let repaired = extract(&bytes, &digest, "9.9.9", &dir).unwrap();
        assert!(cache_matches(&repaired, "9.9.9", &digest));
        assert!(repaired.join("bin/ouroboros").is_file());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unmarked_cache_still_requires_matching_embedded_bytes() {
        let dir = scratch("unmarked-mismatch");
        let bytes = fixture_tarball();
        let digest = sha256_hex(&bytes);
        let release = extract(&bytes, &digest, "9.9.9", &dir).unwrap();
        fs::remove_file(release.join(COMPLETION_MARKER)).unwrap();

        let error = extract(&[], &digest, "9.9.9", &dir).expect_err("unverified cache reuse");
        assert!(error.to_string().contains("does not match the digest"));
        assert!(!release.exists());
        fs::remove_dir_all(&dir).ok();
    }

    /// A directory that carries a digest name without being a release is repaired by
    /// extraction rather than returned to the spawner.
    #[test]
    fn an_unshaped_digest_named_directory_is_replaced_by_a_verified_extraction() {
        let dir = scratch("unshaped");
        let bytes = fixture_tarball();
        let digest = sha256_hex(&bytes);
        let planted = dir.join(directory_name("9.9.9", &digest));

        fs::create_dir_all(planted.join("bin")).unwrap();

        let release = extract(&bytes, &digest, "9.9.9", &dir).expect("the repaired release");

        assert_eq!(release, planted);
        assert!(release.join("releases").join("start_erl.data").is_file());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_or_symlink_cache_entry_is_replaced_without_following_it() {
        for entry in ["file", "dangling-symlink", "directory-symlink"] {
            let dir = scratch(entry);
            let bytes = fixture_tarball();
            let digest = sha256_hex(&bytes);
            let destination = dir.join(directory_name("9.9.9", &digest));
            let outside = dir.join("outside");
            match entry {
                "file" => fs::write(&destination, b"not a release").unwrap(),
                "dangling-symlink" => {
                    std::os::unix::fs::symlink(&outside, &destination).unwrap();
                }
                "directory-symlink" => {
                    fs::create_dir(&outside).unwrap();
                    fs::write(outside.join("sentinel"), b"keep").unwrap();
                    std::os::unix::fs::symlink(&outside, &destination).unwrap();
                }
                _ => unreachable!(),
            }

            let repaired = extract(&bytes, &digest, "9.9.9", &dir).unwrap();
            assert_eq!(repaired, destination);
            assert!(cache_matches(&repaired, "9.9.9", &digest));
            if entry == "directory-symlink" {
                assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"keep");
            } else {
                assert!(!outside.exists());
            }
            fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn a_delayed_invalid_observer_reuses_a_concurrently_completed_repair() {
        let dir = scratch("delayed-repair");
        let bytes = fixture_tarball();
        let digest = sha256_hex(&bytes);
        let destination = dir.join(directory_name("9.9.9", &digest));
        fs::create_dir_all(destination.join("bin")).unwrap();
        fs::create_dir_all(destination.join("releases")).unwrap();
        let (observed, observation) = std::sync::mpsc::channel();
        let (resume, resumed) = std::sync::mpsc::channel();

        std::thread::scope(|scope| {
            let delayed_destination = destination.clone();
            let delayed_digest = digest.clone();
            let delayed_dir = dir.clone();
            let delayed = scope.spawn(move || {
                assert!(!cache_matches(
                    &delayed_destination,
                    "9.9.9",
                    &delayed_digest
                ));
                observed.send(()).unwrap();
                resumed.recv().unwrap();
                // Continue exactly where an initial failed warm lookup enters repair.
                // Empty bytes also prove that the new winner is reused, not extracted.
                extract_uncached(&[], &delayed_digest, "9.9.9", &delayed_dir)
            });

            observation.recv().unwrap();
            let winner = extract(&bytes, &digest, "9.9.9", &dir).unwrap();
            fs::write(winner.join("already-starting"), b"keep").unwrap();
            resume.send(()).unwrap();
            assert_eq!(delayed.join().unwrap().unwrap(), winner);
            assert_eq!(fs::read(winner.join("already-starting")).unwrap(), b"keep");
            assert!(cache_matches(&winner, "9.9.9", &digest));
        });
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_busy_extraction_lock_refuses_and_preserves_its_coordination_inode() {
        use std::os::unix::fs::MetadataExt;

        let dir = scratch("busy-lock");
        let held = lock_extraction(&dir, Duration::ZERO).unwrap();
        let inode = fs::metadata(dir.join(EXTRACTION_LOCK)).unwrap().ino();
        let error = lock_extraction(&dir, Duration::ZERO).expect_err("a bounded lock refusal");
        assert!(error
            .to_string()
            .contains("timed out waiting for release extraction"));
        drop(held);
        let reacquired = lock_extraction(&dir, Duration::ZERO).unwrap();
        assert_eq!(
            fs::metadata(dir.join(EXTRACTION_LOCK)).unwrap().ino(),
            inode
        );
        drop(reacquired);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_releases_directory_is_private_to_its_owner() {
        let dir = scratch("private");
        let releases = dir.join("releases");
        let bytes = fixture_tarball();
        let digest = sha256_hex(&bytes);

        fs::create_dir_all(&releases).unwrap();
        let mut permissions = fs::metadata(&releases).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&releases, permissions).unwrap();

        extract(&bytes, &digest, "9.9.9", &releases).expect("an extracted release");

        let mode = fs::metadata(&releases).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "a shared cache root defeats the data-dir boundary"
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// Collection keeps what was started most recently, not what was unpacked most
    /// recently: a release two upgrades old that a daemon is still running out of would
    /// otherwise be deleted underneath it.
    #[test]
    fn reuse_restamps_a_release_so_collection_spares_it() {
        let dir = scratch("restamp");
        let bytes = fixture_tarball();
        let digest = sha256_hex(&bytes);

        let old = extract(&bytes, &digest, "1.0.0", &dir).expect("the running release");
        filetime(&old, SystemTime::now() - Duration::from_secs(3_600));

        for (age, name) in [(120, "2.0.0+aaaaaaaa"), (60, "3.0.0+bbbbbbbb")] {
            let path = dir.join(name);
            fs::create_dir_all(&path).unwrap();
            filetime(&path, SystemTime::now() - Duration::from_secs(age));
        }

        // Starting out of it again is the use that has to count.
        assert_eq!(extract(&bytes, &digest, "1.0.0", &dir).unwrap(), old);

        gc(&dir, KEEP).expect("a collection");

        assert!(old.is_dir(), "the release just started must survive");
        assert!(!dir.join("2.0.0+aaaaaaaa").exists());
        assert!(dir.join("3.0.0+bbbbbbbb").is_dir());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_bytes_that_do_not_match_the_recorded_digest() {
        let dir = scratch("mismatch");
        let bytes = fixture_tarball();
        let wrong = "0".repeat(64);

        let error = extract(&bytes, &wrong, "9.9.9", &dir).expect_err("a refusal");

        assert!(
            error.to_string().contains("does not match the digest"),
            "unexpected error: {error}"
        );

        let leftovers: Vec<_> = fs::read_dir(&dir)
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();

        assert_eq!(
            leftovers,
            vec![dir.join(EXTRACTION_LOCK)],
            "a refused extraction leaves only the permanent coordination lock"
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// `unpack` is what keeps a cache extraction inside its destination. A member
    /// named `../pwned` must not appear beside the releases directory. The crate
    /// skips such entries rather than returning an error, so extraction may
    /// succeed with an empty directory; the parent must stay clean either way.
    #[test]
    fn an_escaping_archive_member_cannot_write_outside_the_destination() {
        let dir = scratch("escape");
        let releases = dir.join("releases");
        let bytes = escaping_tarball();
        let digest = sha256_hex(&bytes);

        let result = extract(&bytes, &digest, "9.9.9", &releases);
        let planted = dir.join("pwned");
        let sibling = releases.join("pwned");

        assert!(
            result.is_err() || (!planted.exists() && !sibling.exists()),
            "the extractor must refuse an escaping member, or at least not write it \
             outside the destination: {result:?}"
        );
        assert!(
            !planted.exists(),
            "the parent of the releases directory must stay clean"
        );
        assert!(
            !sibling.exists(),
            "an escaping member must not land beside the unpack directory"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn concurrent_extractions_produce_exactly_one_release() {
        let dir = scratch("race");
        let bytes = fixture_tarball();
        let digest = sha256_hex(&bytes);

        let results: Vec<PathBuf> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let dir = dir.clone();
                    let bytes = bytes.clone();
                    let digest = digest.clone();

                    scope.spawn(move || extract(&bytes, &digest, "9.9.9", &dir).expect("extracted"))
                })
                .collect();

            handles
                .into_iter()
                .map(|handle| handle.join().expect("no panic"))
                .collect()
        });

        assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(cache_matches(&results[0], "9.9.9", &digest));

        let entries: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name() != EXTRACTION_LOCK)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            entries,
            vec![format!("9.9.9+{digest}")],
            "the losers of the race must delete their temporary copies"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_rename_race_accepts_only_a_matching_completed_winner() {
        for winner in [
            "matching",
            "missing",
            "wrong-digest",
            "wrong-version",
            "malformed",
        ] {
            let dir = scratch(winner);
            let bytes = fixture_tarball();
            let digest = sha256_hex(&bytes);
            let destination = extract(&bytes, &digest, "9.9.9", &dir).unwrap();
            let temporary = extract(&bytes, &digest, "9.9.9", &dir.join("staging")).unwrap();
            let marker = destination.join(COMPLETION_MARKER);
            match winner {
                "matching" => {}
                "missing" => fs::remove_file(&marker).unwrap(),
                "wrong-digest" => {
                    fs::write(&marker, completion_identity("9.9.9", &"0".repeat(64))).unwrap()
                }
                "wrong-version" => {
                    fs::write(&marker, completion_identity("8.8.8", &digest)).unwrap()
                }
                "malformed" => fs::remove_dir_all(destination.join("bin")).unwrap(),
                _ => unreachable!(),
            }

            // The nonempty destination forces rename to lose, deterministically.
            let result = publish_completed(&temporary, &destination, "9.9.9", &digest);
            assert_eq!(result.is_ok(), winner == "matching", "{winner}: {result:?}");
            assert!(
                !temporary.exists(),
                "the loser removes only its own extraction"
            );
            assert!(
                destination.is_dir(),
                "the race winner is preserved for reconciliation"
            );
            fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn collection_keeps_the_newest_releases_and_the_live_temporaries() {
        let dir = scratch("gc");

        for (index, name) in ["0.1.0+aaaaaaaa", "0.2.0+bbbbbbbb", "0.3.0+cccccccc"]
            .iter()
            .enumerate()
        {
            let path = dir.join(name);
            fs::create_dir_all(&path).unwrap();

            let mut marker = fs::File::create(path.join("marker")).unwrap();
            marker.write_all(b"x").unwrap();

            // Distinct modification times, oldest first.
            let when = SystemTime::now() - Duration::from_secs((3 - index) as u64 * 60);
            filetime(&path, when);
        }

        let live = dir.join(format!(".tmp-{}-0", std::process::id()));
        fs::create_dir_all(&live).unwrap();

        let dead = dir.join(".tmp-2147483646-0");
        fs::create_dir_all(&dead).unwrap();

        let removed = gc(&dir, KEEP).expect("a collection");

        assert!(removed.iter().any(|path| path.ends_with("0.1.0+aaaaaaaa")));
        assert!(removed
            .iter()
            .any(|path| path.ends_with(".tmp-2147483646-0")));

        assert!(dir.join("0.2.0+bbbbbbbb").is_dir());
        assert!(dir.join("0.3.0+cccccccc").is_dir());
        assert!(!dir.join("0.1.0+aaaaaaaa").exists());
        assert!(live.is_dir(), "an extraction still in flight must survive");

        fs::remove_dir_all(&dir).ok();
    }

    /// `utimes` through libc, because the standard library has no way to backdate a
    /// directory and the collection order is what this test is about.
    fn filetime(path: &Path, when: SystemTime) {
        let seconds = when
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("a time after the epoch")
            .as_secs() as libc::time_t;

        let times = [
            libc::timeval {
                tv_sec: seconds,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: seconds,
                tv_usec: 0,
            },
        ];

        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("a path");

        // SAFETY: both pointers are valid for the duration of the call.
        let outcome = unsafe { libc::utimes(path.as_ptr(), times.as_ptr()) };

        assert_eq!(outcome, 0, "backdating the directory must succeed");
    }
}
