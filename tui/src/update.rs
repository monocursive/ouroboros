//! `ouro update`: replace this binary with a signed release, or refuse and say why.
//!
//! ## What each check actually defends against
//!
//! Three different things are checked here and they are not interchangeable, so they are
//! named separately everywhere this module speaks:
//!
//! * **The Ed25519 signature over `SHA256SUMS`** is the only thing that makes a download
//!   *trustworthy*. The key is generated offline, its private half lives in the release
//!   pipeline's secret store, and its public half is compiled into this binary from
//!   [`dist/release.pub`]. It defends against a compromised release host, a hijacked
//!   mirror, a stolen publishing token, and anyone in a position to hand this process
//!   different bytes than the project published.
//! * **The SHA-256 of the downloaded asset**, checked against an entry in that *signed*
//!   file, extends the signature's authority to the binary itself. Checked on its own it
//!   would defend against nothing an attacker cares about — a checksum fetched from the
//!   same place as the binary is a checksum an attacker who can replace the binary can
//!   also replace. It is a real check here only because the file it comes from was
//!   signed first, and this module never runs it without the signature.
//! * **TLS**, when the transport happens to be HTTPS, defends the *download* — it says
//!   which host answered and keeps the bytes private in flight. It says nothing about
//!   whether the project made those bytes. That is why the transport below is allowed to
//!   be a subprocess, and why the signature is not.
//!
//! Consequently: a build with no release public key refuses every path through this
//! command, including `--check`. There is no "verification skipped" mode, because a
//! version number this process cannot authenticate is not a fact it should report as
//! one.
//!
//! ## Why HTTP is `curl`, and not a crate
//!
//! This client has no HTTP stack: it speaks the gateway's line protocol over raw TCP.
//! Adding one (`reqwest`/`ureq` + `rustls` + a webpki root store) to fetch four files
//! once in a while is a large new tree carrying the *transport* half of the problem —
//! the half that, per the paragraph above, is not what makes an update safe. So the
//! transport is `curl` (then `wget`), which every target platform already ships, which
//! honours `http_proxy`/`https_proxy`/`no_proxy` from the environment without this
//! module reimplementing proxy semantics, and which bounds itself (`--max-time`,
//! `--max-filesize`, `--proto`). The part that cannot be delegated — the signature — is
//! verified in-process by `ring`, which this crate already depends on for the fleet's
//! TLS identities.
//!
//! ## Replacement is a rename, and that is not an implementation detail
//!
//! A running executable cannot be written into on Linux (`ETXTBSY`) and must not be on
//! macOS, where the pager may still fault pages of it in. Its *directory entry* can be
//! replaced at any time: POSIX `rename(2)` is atomic within a filesystem, the running
//! image keeps the inode it was started from, and the next `exec` finds the new one. So
//! the download lands beside the target, is verified there, and is renamed over it. No
//! window exists in which the destination name refers to a partially written file, and a
//! failure at any earlier point leaves the installed binary untouched.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// The trust root, read at compile time.
///
/// `include_str!` rather than a build script so that the file a reader can see in the
/// tree is provably the file that ends up in the binary, and so that editing it rebuilds
/// this crate. `OURO_RELEASE_PUBKEY` lets a fork bake its own key without editing a
/// tracked file; it is a *build-time* input on purpose — nothing an already-built binary
/// reads from its environment can move the trust root, or the trust root would be
/// whatever the caller says it is.
const RELEASE_PUBLIC_KEY_SOURCE: &str = match option_env!("OURO_RELEASE_PUBKEY") {
    Some(inline) => inline,
    None => include_str!("../../dist/release.pub"),
};

/// Where a release is fetched from when `--from` is not given.
///
/// `None` in this tree, and that is a fact rather than an oversight: the configured git
/// remote is not a public release host, so there is no URL to put here that would be
/// true. `ouro update` therefore requires `--from` until one exists, instead of shipping
/// a default that 404s. Set `OURO_RELEASE_BASE_URL` at build time to the directory
/// holding `ouro-<version>-<triple>`, `SHA256SUMS`, and `SHA256SUMS.minisig` — for a
/// GitHub project that is
/// `https://github.com/<owner>/<repo>/releases/latest/download`.
const DEFAULT_BASE_URL: Option<&str> = option_env!("OURO_RELEASE_BASE_URL");

/// The signed manifest of asset digests.
pub const SUMS_NAME: &str = "SHA256SUMS";

/// The detached minisign signature over [`SUMS_NAME`].
pub const SIGNATURE_NAME: &str = "SHA256SUMS.minisig";

/// Caps. A download is bounded before it is read, not after, because "we ran out of disk
/// deciding whether to trust you" is a denial of service with extra steps.
const SUMS_CAP: u64 = 1 << 20; // 1 MiB
const SIGNATURE_CAP: u64 = 16 << 10; // 16 KiB
/// The asset carries a whole OTP release, so it is tens of megabytes; half a gigabyte is
/// far above any plausible one and far below "fills the disk".
const ASSET_CAP: u64 = 512 << 20;

/// Seconds. Small files are quick or they are wrong; the asset gets a real budget.
const SMALL_TIMEOUT: u64 = 60;
const ASSET_TIMEOUT: u64 = 900;
const CONNECT_TIMEOUT: u64 = 20;

/// The triples the release matrix builds. A binary carries the OTP release of the
/// machine that built it, so these are the only names an asset can honestly have.
pub const TRIPLES: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
];

/// The process exit code this command ended with, carried as an error so `main` can
/// honour it. Every value is documented in `ouro update --help` and in
/// `docs/DISTRIBUTION.md`; a script that branches on them is entitled to expect them to
/// keep meaning what they mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit(u8);

impl Exit {
    /// Updated, already current, or `--check` found nothing newer.
    pub const OK: Exit = Exit(0);
    /// `--check` only: a newer release exists.
    pub const AVAILABLE: Exit = Exit(10);
    /// This build carries no release public key, so nothing can be verified.
    pub const NO_KEY: Exit = Exit(11);
    /// A signature, a digest, or the shape of a signed file did not check out.
    pub const VERIFICATION: Exit = Exit(12);
    /// The release is older than the running binary and `--allow-downgrade` was absent.
    pub const DOWNGRADE: Exit = Exit(13);
    /// The installed binary is not this command's to replace.
    pub const NOT_WRITABLE: Exit = Exit(14);
    /// Nothing could be fetched: no source configured, or the transport failed.
    pub const TRANSPORT: Exit = Exit(15);
    /// The release has no asset for this platform.
    pub const NO_ASSET: Exit = Exit(16);

    pub fn code(self) -> u8 {
        self.0
    }
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ouro update exited {}", self.0)
    }
}

impl std::error::Error for Exit {}

/// A refusal: the code to exit with and the sentence to say first.
#[derive(Debug)]
pub struct Refusal {
    pub exit: Exit,
    pub message: String,
}

impl Refusal {
    fn new(exit: Exit, message: impl Into<String>) -> Self {
        Self {
            exit,
            message: message.into(),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Refusal {}

/// What was typed.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Report versions and exit; download nothing, replace nothing.
    pub check: bool,
    /// A base URL or directory holding the release assets. Overrides the compiled-in
    /// default, which is how mirrors and local staging directories are used.
    pub from: Option<String>,
    /// Install a release older than the running binary.
    pub allow_downgrade: bool,
}

/// What happened, for a caller that wants the facts rather than the printed page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `--check`: the release is not newer than the running binary.
    Current { running: Version, release: Version },
    /// `--check`: it is.
    Available { running: Version, release: Version },
    /// The running binary was replaced.
    Updated {
        running: Version,
        release: Version,
        path: PathBuf,
    },
    /// Nothing to do: the release names the version already installed.
    AlreadyInstalled { running: Version },
}

impl Outcome {
    pub fn exit(&self) -> Exit {
        match self {
            Outcome::Available { .. } => Exit::AVAILABLE,
            _ => Exit::OK,
        }
    }
}

// ---------------------------------------------------------------------------------
// The trust root
// ---------------------------------------------------------------------------------

/// The release public key this binary was built with, or `None` when it was built
/// without one. `None` is a refusal everywhere, never a relaxation.
pub fn release_public_key() -> Option<PublicKey> {
    PublicKey::parse(RELEASE_PUBLIC_KEY_SOURCE).ok()
}

/// Distinguishes "no key was provisioned" from "a key was provisioned and is broken".
///
/// Both refuse, and both refuse with the same exit code, because the consequence is
/// identical: nothing can be verified. But they send a person to different places — one
/// to the provisioning procedure, one to a build that is wrong — and a refusal that names
/// the wrong problem costs somebody an afternoon.
fn key_is_present_but_unusable() -> Option<String> {
    key_line(RELEASE_PUBLIC_KEY_SOURCE)?;

    PublicKey::parse(RELEASE_PUBLIC_KEY_SOURCE)
        .err()
        .map(|error| format!("{error:#}"))
}

// ---------------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------------

/// The release triple for the machine this process is running on.
///
/// Derived from what the compiler baked in rather than from `uname`, because the
/// question is "which build is *this* binary's successor", and a binary knows that about
/// itself with certainty.
pub fn host_triple() -> Option<&'static str> {
    triple_for(std::env::consts::OS, std::env::consts::ARCH)
}

/// Split out so the mapping is testable for platforms this test run is not on.
pub fn triple_for(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        _ => None,
    }
}

/// The version this binary was compiled as.
pub fn running_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION"))
        .expect("the crate's own version is a version this parser accepts")
}

// ---------------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------------

/// A SemVer-shaped version, compared the way SemVer says to.
///
/// Build metadata is parsed and then ignored in comparison, which is what the spec
/// requires: `1.0.0+a` and `1.0.0+b` are the same release built twice, not two releases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Dot-separated pre-release identifiers. Empty means a final release.
    pub pre: Vec<String>,
}

impl Version {
    pub fn parse(text: &str) -> Option<Version> {
        let text = text.trim();

        // Build metadata never participates in ordering, so it is discarded here rather
        // than carried into a comparison that would have to remember to ignore it.
        let core = text.split('+').next().unwrap_or(text);

        // `Some("")` and `None` are different things: `1.2.3-` carries an empty
        // pre-release identifier and is not a version, while `1.2.3` carries none and is.
        // Collapsing them would make the two strings parse to the same value.
        let (core, pre) = match core.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (core, None),
        };

        let mut fields = core.split('.');
        let major = fields.next()?.parse().ok()?;
        let minor = fields.next()?.parse().ok()?;
        let patch = fields.next()?.parse().ok()?;

        if fields.next().is_some() {
            return None;
        }

        let pre: Vec<String> = match pre {
            None => Vec::new(),
            Some(pre) => pre.split('.').map(str::to_string).collect(),
        };

        // An empty identifier (`1.0.0-`, `1.0.0-a..b`) is not a version, and silently
        // accepting one would make two different strings compare equal.
        if pre.iter().any(String::is_empty) {
            return None;
        }

        Some(Version {
            major,
            minor,
            patch,
            pre,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;

        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre.join("."))?;
        }

        Ok(())
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        let core =
            (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch));

        if core != Ordering::Equal {
            return core;
        }

        // A pre-release precedes the release it leads to: 1.0.0-rc.1 < 1.0.0.
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => compare_pre(&self.pre, &other.pre),
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// SemVer §11.4: numeric identifiers compare numerically and rank below alphanumeric
/// ones; a shorter prefix ranks lower.
fn compare_pre(left: &[String], right: &[String]) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    for (left, right) in left.iter().zip(right.iter()) {
        let ordering = match (left.parse::<u64>(), right.parse::<u64>()) {
            (Ok(left), Ok(right)) => left.cmp(&right),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => left.cmp(right),
        };

        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    left.len().cmp(&right.len())
}

// ---------------------------------------------------------------------------------
// The signed sums file
// ---------------------------------------------------------------------------------

/// One `<digest>  <name>` line of a `sha256sum` manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumEntry {
    pub digest: [u8; 32],
    pub name: String,
}

/// Parses a `sha256sum`-format manifest.
///
/// Strict on purpose. This file has already been proven to come from the release key by
/// the time it is parsed, so anything unexpected in it is either a pipeline bug or an
/// attempt to smuggle ambiguity past a signature — two names for one asset, or a name
/// that is really a path. Both are refusals, not warnings.
pub fn parse_sums(text: &str) -> Result<Vec<SumEntry>> {
    let mut entries: Vec<SumEntry> = Vec::new();

    for (number, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');

        if line.trim().is_empty() {
            continue;
        }

        let number = number + 1;

        let (digest, name) = line
            .split_once("  ")
            .or_else(|| line.split_once(" *"))
            .ok_or_else(|| {
                anyhow!("{SUMS_NAME} line {number} is not `<sha256>  <name>`: {line:?}")
            })?;

        let digest = decode_sha256(digest)
            .with_context(|| format!("{SUMS_NAME} line {number} does not start with a digest"))?;

        let name = name.trim();

        if name.is_empty() || name.contains('/') || name.contains('\\') || name.starts_with('.') {
            return Err(anyhow!(
                "{SUMS_NAME} line {number} names {name:?}, which is a path rather than an \
                 asset in this release"
            ));
        }

        if let Some(existing) = entries.iter().find(|entry| entry.name == name) {
            if existing.digest == digest {
                return Err(anyhow!(
                    "{SUMS_NAME} lists {name} twice; a signed manifest that repeats itself \
                     is a pipeline that ran twice"
                ));
            }

            return Err(anyhow!(
                "{SUMS_NAME} gives {name} two different digests; refusing to choose one"
            ));
        }

        entries.push(SumEntry {
            digest,
            name: name.to_string(),
        });
    }

    if entries.is_empty() {
        return Err(anyhow!("{SUMS_NAME} lists no assets"));
    }

    Ok(entries)
}

fn decode_sha256(text: &str) -> Result<[u8; 32]> {
    let text = text.trim();

    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!("{text:?} is not 64 hexadecimal digits"));
    }

    let mut digest = [0_u8; 32];

    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .expect("every pair was checked to be hexadecimal");
    }

    Ok(digest)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The single version a manifest describes.
///
/// Asset names carry the version, so the release announces its own version inside the
/// file the signature covers — there is no second, unsigned place to ask. A manifest
/// naming two versions is refused rather than resolved: choosing the higher one would
/// let anybody who can append a line to a *future* signed file steer this command.
pub fn release_version(entries: &[SumEntry]) -> Result<Version> {
    let mut found: Option<Version> = None;

    for entry in entries {
        let Some(version) = version_of_asset(&entry.name) else {
            continue;
        };

        match &found {
            None => found = Some(version),
            Some(existing) if *existing == version => {}
            Some(existing) => {
                return Err(anyhow!(
                    "{SUMS_NAME} names both {existing} and {version}; one release, one version"
                ))
            }
        }
    }

    found.ok_or_else(|| {
        anyhow!("{SUMS_NAME} holds no `ouro-<version>-<triple>` asset for any supported platform")
    })
}

/// `ouro-0.2.0-aarch64-apple-darwin` → `0.2.0`.
pub fn version_of_asset(name: &str) -> Option<Version> {
    let rest = name.strip_prefix("ouro-")?;

    for triple in TRIPLES {
        if let Some(version) = rest.strip_suffix(triple).and_then(|v| v.strip_suffix('-')) {
            return Version::parse(version);
        }
    }

    None
}

pub fn asset_name(version: &Version, triple: &str) -> String {
    format!("ouro-{version}-{triple}")
}

// ---------------------------------------------------------------------------------
// minisign
// ---------------------------------------------------------------------------------

/// Legacy: the Ed25519 signature covers the file's bytes.
const ALG_ED25519: [u8; 2] = *b"Ed";
/// Prehashed: it covers BLAKE2b-512 of the file's bytes. Current `minisign` writes this
/// by default, older versions wrote the legacy form, and this module accepts either so a
/// signature is not silently rejected because the pipeline's `minisign` was upgraded.
const ALG_ED25519_PREHASHED: [u8; 2] = *b"ED";

/// A minisign public key: 2 bytes of algorithm, 8 bytes of key id, 32 bytes of Ed25519.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    key_id: [u8; 8],
    key: [u8; 32],
}

impl PublicKey {
    /// Parses `dist/release.pub`, or anything shaped like it.
    ///
    /// The `untrusted comment:` header and this project's `#` annotations are skipped;
    /// the first line that is neither is the key. A file with no such line is not an
    /// error to *read* — it is the unprovisioned state — but it yields `Err` here so
    /// that no caller can accidentally treat "no key" as "any key".
    pub fn parse(text: &str) -> Result<PublicKey> {
        let line = key_line(text).ok_or_else(|| {
            anyhow!(
                "no minisign public key: this build carries no release signing key, so there \
                 is nothing for a release signature to be checked against"
            )
        })?;

        let bytes = BASE64
            .decode(line.trim())
            .context("the release public key is not base64")?;

        if bytes.len() != 42 {
            return Err(anyhow!(
                "a minisign public key is 42 bytes (algorithm, key id, key); this one is {}",
                bytes.len()
            ));
        }

        if bytes[0..2] != ALG_ED25519 {
            return Err(anyhow!(
                "the release public key names algorithm {:?}, and only Ed25519 (\"Ed\") is \
                 understood",
                String::from_utf8_lossy(&bytes[0..2])
            ));
        }

        let mut key_id = [0_u8; 8];
        key_id.copy_from_slice(&bytes[2..10]);

        let mut key = [0_u8; 32];
        key.copy_from_slice(&bytes[10..42]);

        Ok(PublicKey { key_id, key })
    }

    /// The key id as `minisign` prints it: the eight bytes read as a little-endian
    /// integer and formatted in uppercase hexadecimal, which is the byte order reversed.
    pub fn id(&self) -> String {
        self.key_id
            .iter()
            .rev()
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }
}

/// A detached `.minisig`.
#[derive(Debug, Clone)]
pub struct Signature {
    algorithm: [u8; 2],
    key_id: [u8; 8],
    signature: [u8; 64],
    /// The comment the *signer* covered by a second signature. Safe to display after
    /// verification, and only then.
    trusted_comment: String,
    global_signature: [u8; 64],
}

impl Signature {
    pub fn parse(text: &str) -> Result<Signature> {
        let mut lines = text.lines().filter(|line| !line.trim().is_empty());

        let _untrusted = lines
            .next()
            .ok_or_else(|| anyhow!("the signature file is empty"))?;

        let signature = lines
            .next()
            .ok_or_else(|| anyhow!("the signature file has no signature line"))?;

        let trusted = lines
            .next()
            .ok_or_else(|| anyhow!("the signature file has no trusted comment"))?;

        let global = lines
            .next()
            .ok_or_else(|| anyhow!("the signature file has no global signature"))?;

        let signature = BASE64
            .decode(signature.trim())
            .context("the signature line is not base64")?;

        if signature.len() != 74 {
            return Err(anyhow!(
                "a minisign signature is 74 bytes (algorithm, key id, signature); this one \
                 is {}",
                signature.len()
            ));
        }

        let trusted_comment = trusted
            .strip_prefix("trusted comment: ")
            .ok_or_else(|| anyhow!("the third line is not a `trusted comment: ` line"))?
            .to_string();

        let global = BASE64
            .decode(global.trim())
            .context("the global signature line is not base64")?;

        if global.len() != 64 {
            return Err(anyhow!(
                "a minisign global signature is 64 bytes; this one is {}",
                global.len()
            ));
        }

        let mut algorithm = [0_u8; 2];
        algorithm.copy_from_slice(&signature[0..2]);

        let mut key_id = [0_u8; 8];
        key_id.copy_from_slice(&signature[2..10]);

        let mut bytes = [0_u8; 64];
        bytes.copy_from_slice(&signature[10..74]);

        let mut global_signature = [0_u8; 64];
        global_signature.copy_from_slice(&global);

        Ok(Signature {
            algorithm,
            key_id,
            signature: bytes,
            trusted_comment,
            global_signature,
        })
    }
}

/// Verifies a detached minisign signature and returns the comment it authenticates.
///
/// Three things are checked and all three are load-bearing:
///
/// 1. the signature names *this* key, so a valid signature by some other key is a
///    refusal rather than a pass;
/// 2. the Ed25519 signature over the message (or over its BLAKE2b-512 hash, for the
///    prehashed form) — the actual proof;
/// 3. the *global* signature over `signature || trusted comment`, without which the
///    trusted comment would be attacker-chosen text this command then printed as though
///    the project had written it.
pub fn verify<'a>(key: &PublicKey, signature: &'a Signature, message: &[u8]) -> Result<&'a str> {
    use ring::signature::{UnparsedPublicKey, ED25519};

    if signature.key_id != key.key_id {
        let mut theirs = signature.key_id;
        theirs.reverse();

        return Err(anyhow!(
            "the signature was made by key {} and this build trusts key {}",
            theirs
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>(),
            key.id()
        ));
    }

    let signed: Vec<u8> = match signature.algorithm {
        ALG_ED25519 => message.to_vec(),
        ALG_ED25519_PREHASHED => blake2b512(message).to_vec(),
        other => {
            return Err(anyhow!(
                "unknown minisign algorithm {:?}",
                String::from_utf8_lossy(&other)
            ))
        }
    };

    let public = UnparsedPublicKey::new(&ED25519, key.key.as_slice());

    public.verify(&signed, &signature.signature).map_err(|_| {
        anyhow!(
            "the release signature does not check out against key {}: these bytes were not \
             signed by the Ouroboros release key",
            key.id()
        )
    })?;

    // The trusted comment is only trusted because of this.
    let mut global = Vec::with_capacity(64 + signature.trusted_comment.len());
    global.extend_from_slice(&signature.signature);
    global.extend_from_slice(signature.trusted_comment.as_bytes());

    public
        .verify(&global, &signature.global_signature)
        .map_err(|_| {
            anyhow!(
                "the signature's trusted comment is not covered by key {}; refusing to \
                 report an unauthenticated comment as trusted",
                key.id()
            )
        })?;

    Ok(&signature.trusted_comment)
}

fn blake2b512(message: &[u8]) -> [u8; 64] {
    use blake2::digest::consts::U64;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U64>::new();
    hasher.update(message);

    let digest = hasher.finalize();
    let mut out = [0_u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// The first line of a minisign key or comment block that is neither the header nor one
/// of this project's `#` annotations.
fn key_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|line| {
        !line.is_empty()
            && !line.starts_with('#')
            && !line.starts_with("untrusted comment:")
            && !line.starts_with("trusted comment:")
    })
}

// ---------------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------------

/// Where the release assets are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A directory on this machine. `file://` URLs and plain paths land here, which is
    /// what makes every test in this module network-free.
    Directory(PathBuf),
    /// An HTTP(S) base URL, fetched by a subprocess.
    Url(String),
}

impl Source {
    pub fn parse(base: &str) -> Result<Source> {
        let base = base.trim();

        if let Some(path) = base.strip_prefix("file://") {
            // `file:///abs` leaves a leading slash, which is the path. `file://host/...`
            // is refused rather than guessed at.
            if !path.starts_with('/') {
                return Err(anyhow!(
                    "{base} names a host; only local `file:///absolute/path` URLs are read"
                ));
            }

            return Ok(Source::Directory(PathBuf::from(path)));
        }

        if base.starts_with("https://") || base.starts_with("http://") {
            return Ok(Source::Url(base.trim_end_matches('/').to_string()));
        }

        if base.contains("://") {
            return Err(anyhow!(
                "{base} is not a scheme this command fetches; use https://, http://, \
                 file:///, or a directory path"
            ));
        }

        Ok(Source::Directory(PathBuf::from(base)))
    }

    pub fn describe(&self) -> String {
        match self {
            Source::Directory(path) => path.display().to_string(),
            Source::Url(url) => url.clone(),
        }
    }

    /// True when the bytes arrive over a transport that authenticates the host. Not a
    /// trust decision — the signature is — but worth saying out loud.
    pub fn transport_is_authenticated(&self) -> bool {
        match self {
            Source::Directory(_) => true,
            Source::Url(url) => url.starts_with("https://"),
        }
    }

    fn fetch_to(&self, name: &str, destination: &Path, cap: u64, timeout: u64) -> Result<u64> {
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(anyhow!("{name:?} is not an asset name"));
        }

        match self {
            Source::Directory(directory) => {
                let source = directory.join(name);

                let length = fs::metadata(&source)
                    .with_context(|| format!("reading {}", source.display()))?
                    .len();

                if length > cap {
                    return Err(anyhow!(
                        "{} is {length} bytes and the cap for it is {cap}",
                        source.display()
                    ));
                }

                let mut reader =
                    File::open(&source).with_context(|| format!("opening {}", source.display()))?;

                // `create_new` rather than `fs::copy`, so a symlink planted at the
                // destination is an error instead of a write somewhere else.
                let mut writer = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(destination)
                    .with_context(|| format!("creating {}", destination.display()))?;

                io::copy(&mut reader, &mut writer).with_context(|| {
                    format!("copying {} to {}", source.display(), destination.display())
                })?;

                writer
                    .sync_all()
                    .with_context(|| format!("flushing {}", destination.display()))?;

                Ok(length)
            }
            Source::Url(base) => {
                let url = format!("{base}/{name}");
                download(&url, destination, cap, timeout)?;

                let length = fs::metadata(destination)?.len();

                // `wget` cannot be told a size cap up front and `curl` can only enforce
                // one when the server declared a length, so the cap is also enforced on
                // what actually landed.
                if length > cap {
                    let _ = fs::remove_file(destination);
                    return Err(anyhow!("{url} delivered {length} bytes; the cap is {cap}"));
                }

                Ok(length)
            }
        }
    }

    fn fetch_bytes(&self, name: &str, cap: u64, scratch: &Path) -> Result<Vec<u8>> {
        let destination = scratch.join(name);
        self.fetch_to(name, &destination, cap, SMALL_TIMEOUT)?;

        let bytes =
            fs::read(&destination).with_context(|| format!("reading {}", destination.display()))?;

        let _ = fs::remove_file(&destination);

        Ok(bytes)
    }
}

/// One HTTP GET, bounded, into a file.
fn download(url: &str, destination: &Path, cap: u64, timeout: u64) -> Result<()> {
    // `--proto` and `--proto-redir` keep a redirect from walking the fetch down to a
    // scheme the caller did not ask for; `-L` is needed because release hosts redirect
    // downloads to an object store.
    let protocols = if url.starts_with("https://") {
        "=https"
    } else {
        "=http,https"
    };

    let agent = format!("ouro/{}", env!("CARGO_PKG_VERSION"));

    if let Some(curl) = which("curl") {
        let output = Command::new(curl)
            .arg("--fail")
            .arg("--silent")
            .arg("--show-error")
            .arg("--location")
            .arg("--proto")
            .arg(protocols)
            .arg("--proto-redir")
            .arg(protocols)
            .arg("--connect-timeout")
            .arg(CONNECT_TIMEOUT.to_string())
            .arg("--max-time")
            .arg(timeout.to_string())
            .arg("--max-filesize")
            .arg(cap.to_string())
            .arg("--user-agent")
            .arg(&agent)
            .arg("--output")
            .arg(destination)
            .arg("--")
            .arg(url)
            .output()
            .with_context(|| format!("running curl for {url}"))?;

        if !output.status.success() {
            let _ = fs::remove_file(destination);
            let stderr = String::from_utf8_lossy(&output.stderr);

            let detail = if stderr.trim().is_empty() {
                output.status.to_string()
            } else {
                stderr.trim().to_string()
            };

            return Err(anyhow!("curl could not fetch {url}: {detail}"));
        }

        return Ok(());
    }

    if let Some(wget) = which("wget") {
        let output = Command::new(wget)
            .arg("--quiet")
            .arg("--tries=1")
            .arg(format!("--timeout={timeout}"))
            .arg("--user-agent")
            .arg(&agent)
            .arg("--output-document")
            .arg(destination)
            .arg("--")
            .arg(url)
            .output()
            .with_context(|| format!("running wget for {url}"))?;

        if !output.status.success() {
            let _ = fs::remove_file(destination);
            let stderr = String::from_utf8_lossy(&output.stderr);

            return Err(anyhow!("wget could not fetch {url}: {}", stderr.trim()));
        }

        return Ok(());
    }

    Err(anyhow!(
        "neither curl nor wget is on PATH, and this client has no HTTP stack of its own \
         (see the module note in tui/src/update.rs). Install one, or download the release \
         by hand and pass the directory to --from"
    ))
}

fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;

    std::env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

// ---------------------------------------------------------------------------------
// Replacing the running binary
// ---------------------------------------------------------------------------------

/// The name a staged download is written under, beside the binary it will replace.
fn staging_path(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ouro".to_string());

    let directory = target.parent().unwrap_or_else(|| Path::new("."));

    directory.join(format!(".{name}.update-{}", std::process::id()))
}

/// Renames a verified file over the installed binary.
///
/// Everything that can fail has failed by now: the caller verified the staged file
/// before calling. What is left is one `rename(2)`, which either happens or does not.
pub fn publish(staged: &Path, target: &Path) -> Result<()> {
    // Keep whatever mode the installed binary had, so a deliberately private install
    // (0700) does not become world-executable because it was updated. A target with no
    // mode to copy gets the ordinary one.
    let mode = fs::metadata(target)
        .map(|metadata| metadata.permissions().mode() & 0o7777)
        .unwrap_or(0o755);

    fs::set_permissions(staged, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting the mode on {}", staged.display()))?;

    fs::rename(staged, target)
        .with_context(|| format!("renaming {} over {}", staged.display(), target.display()))?;

    // The rename is ordered after the file's own contents (the staged file was fsynced
    // before this) and the directory entry is fsynced after it, so a power loss leaves
    // either the old binary or the new one, never a name pointing at nothing.
    if let Some(directory) = target.parent() {
        if let Ok(handle) = File::open(directory) {
            let _ = handle.sync_all();
        }
    }

    Ok(())
}

/// Writes bytes to a staged path with the durability the rename above assumes.
pub fn stage(staged: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(staged)
        .with_context(|| format!("creating {}", staged.display()))?;

    file.write_all(bytes)
        .with_context(|| format!("writing {}", staged.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing {}", staged.display()))?;

    Ok(())
}

/// Package managers own the files they install. Replacing one behind their back leaves a
/// manifest that disagrees with the disk, and the next `upgrade` silently reverts the
/// update — so this is named and refused rather than attempted.
fn managed_by(path: &Path) -> Option<&'static str> {
    let text = path.to_string_lossy();

    if text.contains("/Cellar/") {
        return Some("Homebrew");
    }

    if text.starts_with("/nix/store/") {
        return Some("Nix");
    }

    if text.contains("/.linuxbrew/") || text.contains("/linuxbrew/") {
        return Some("Homebrew");
    }

    None
}

/// A cheap shape check on a downloaded asset.
///
/// Not security — the signature is — but it turns "a proxy served an HTML error page
/// with a 200" into a clear refusal instead of an unrunnable binary on `PATH`.
fn looks_executable(head: &[u8]) -> bool {
    const MACH_O: [[u8; 4]; 5] = [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe], // universal
    ];

    if head.len() < 4 {
        return false;
    }

    if head.starts_with(b"\x7fELF") {
        return true;
    }

    MACH_O.iter().any(|magic| head.starts_with(magic))
}

fn sha256_of_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0_u8; 1 << 16];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("reading {}", path.display()))?;

        if read == 0 {
            break;
        }

        context.update(&buffer[..read]);
    }

    let mut digest = [0_u8; 32];
    digest.copy_from_slice(context.finish().as_ref());

    Ok(digest)
}

// ---------------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------------

/// `ouro update`, printing to `out` and refusing through [`Refusal`].
pub fn perform(
    options: &Options,
    key: Option<&PublicKey>,
    out: &mut dyn Write,
) -> std::result::Result<Outcome, Refusal> {
    perform_into(options, key, None, out)
}

/// The same command, told which file to replace.
///
/// `None` means the binary this process was started from, which is what the subcommand
/// passes. Naming a path instead is how one install updates another — and how the tests
/// exercise the real download-verify-rename path without a test harness replacing
/// itself.
pub fn perform_into(
    options: &Options,
    key: Option<&PublicKey>,
    target: Option<&Path>,
    out: &mut dyn Write,
) -> std::result::Result<Outcome, Refusal> {
    let key = key.ok_or_else(|| {
        Refusal::new(
            Exit::NO_KEY,
            "ouro update: this build carries no release signing key, so it cannot tell a \
             release from anything else offered under the same name — refusing.\n\
             Nothing was downloaded and nothing was verified. Install from a source you \
             checked yourself (see docs/DISTRIBUTION.md), or build from a tree whose \
             dist/release.pub holds the project's key.",
        )
    })?;

    let base = options
        .from
        .as_deref()
        .or(DEFAULT_BASE_URL)
        .ok_or_else(|| {
            Refusal::new(
                Exit::TRANSPORT,
                "ouro update: this build has no release download location compiled in, \
                 because this repository does not publish to one yet. Pass --from <url|dir> \
                 to name a release directory (docs/DISTRIBUTION.md).",
            )
        })?;

    let source = Source::parse(base)
        .map_err(|error| Refusal::new(Exit::TRANSPORT, format!("ouro update: {error:#}")))?;

    let triple = host_triple().ok_or_else(|| {
        Refusal::new(
            Exit::NO_ASSET,
            format!(
                "ouro update: releases are built for {}, and this is {}/{} — refusing.",
                TRIPLES.join(", "),
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        )
    })?;

    let scratch = scratch_directory()
        .map_err(|error| Refusal::new(Exit::TRANSPORT, format!("ouro update: {error:#}")))?;

    let result = run_verified(options, key, &source, triple, target, &scratch, out);

    let _ = fs::remove_dir_all(&scratch);

    result
}

#[allow(clippy::too_many_arguments)]
fn run_verified(
    options: &Options,
    key: &PublicKey,
    source: &Source,
    triple: &str,
    target: Option<&Path>,
    scratch: &Path,
    out: &mut dyn Write,
) -> std::result::Result<Outcome, Refusal> {
    let running = running_version();

    let _ = writeln!(out, "ouro update");
    let _ = writeln!(out, "  source    {}", source.describe());

    if !source.transport_is_authenticated() {
        let _ = writeln!(
            out,
            "            (plain HTTP: the transport is unauthenticated. The release \
             signature below is what makes these bytes trustworthy, not the connection.)"
        );
    }

    let sums = source
        .fetch_bytes(SUMS_NAME, SUMS_CAP, scratch)
        .map_err(|error| {
            Refusal::new(
                Exit::TRANSPORT,
                format!("ouro update: could not fetch {SUMS_NAME}: {error:#}"),
            )
        })?;

    let signature = source
        .fetch_bytes(SIGNATURE_NAME, SIGNATURE_CAP, scratch)
        .map_err(|error| {
            Refusal::new(
                Exit::TRANSPORT,
                format!("ouro update: could not fetch {SIGNATURE_NAME}: {error:#}"),
            )
        })?;

    let signature = String::from_utf8(signature)
        .map_err(|_| anyhow!("{SIGNATURE_NAME} is not text"))
        .and_then(|text| Signature::parse(&text))
        .map_err(|error| {
            Refusal::new(
                Exit::VERIFICATION,
                format!("ouro update: {SIGNATURE_NAME} is malformed: {error:#}"),
            )
        })?;

    let trusted = verify(key, &signature, &sums).map_err(|error| {
        Refusal::new(
            Exit::VERIFICATION,
            format!("ouro update: refusing this release — {error:#}.\nNothing was installed."),
        )
    })?;

    let _ = writeln!(
        out,
        "  signature ok, Ed25519 key {} (dist/release.pub)",
        key.id()
    );
    let _ = writeln!(out, "  signed    {trusted}");

    let entries = String::from_utf8(sums)
        .map_err(|_| anyhow!("{SUMS_NAME} is not text"))
        .and_then(|text| parse_sums(&text))
        .map_err(|error| {
            Refusal::new(
                Exit::VERIFICATION,
                format!("ouro update: the signed {SUMS_NAME} is unusable: {error:#}"),
            )
        })?;

    let release = release_version(&entries)
        .map_err(|error| Refusal::new(Exit::VERIFICATION, format!("ouro update: {error:#}")))?;

    let _ = writeln!(out, "  running   {running}");
    let _ = writeln!(out, "  release   {release}");

    if options.check {
        return if release > running {
            let _ = writeln!(out, "an update is available: {running} -> {release}");
            Ok(Outcome::Available { running, release })
        } else {
            let _ = writeln!(
                out,
                "no update: {running} is at least as new as the published {release}"
            );
            Ok(Outcome::Current { running, release })
        };
    }

    if release == running {
        let _ = writeln!(out, "already installed: {running}");
        return Ok(Outcome::AlreadyInstalled { running });
    }

    if release < running && !options.allow_downgrade {
        return Err(Refusal::new(
            Exit::DOWNGRADE,
            format!(
                "ouro update: the published release is {release} and this binary is \
                 {running}. Installing it would be a downgrade, which is a rollback and \
                 not an update — pass --allow-downgrade if that is what you mean."
            ),
        ));
    }

    let asset = asset_name(&release, triple);

    let entry = entries
        .iter()
        .find(|entry| entry.name == asset)
        .ok_or_else(|| {
            Refusal::new(
                Exit::NO_ASSET,
                format!("ouro update: release {release} has no {asset} in its signed {SUMS_NAME}"),
            )
        })?;

    let target = match target {
        Some(target) => target.to_path_buf(),
        None => installed_path()
            .map_err(|error| Refusal::new(Exit::NOT_WRITABLE, format!("ouro update: {error:#}")))?,
    };

    if let Some(manager) = managed_by(&target) {
        return Err(Refusal::new(
            Exit::NOT_WRITABLE,
            format!(
                "ouro update: {} was installed by {manager}, which owns that file. \
                 Replacing it here would leave {manager}'s manifest disagreeing with the \
                 disk and the next upgrade would silently revert this one. Use \
                 {manager}'s own upgrade command.",
                target.display()
            ),
        ));
    }

    let directory = target.parent().unwrap_or_else(|| Path::new("."));

    if !writable(directory) {
        return Err(Refusal::new(
            Exit::NOT_WRITABLE,
            format!(
                "ouro update: {} is not writable by this user, and this command never asks \
                 for root — a self-updater that can escalate is a self-updater that is one \
                 bug away from owning the machine.\nInstall {asset} into a directory you \
                 own instead: mkdir -p ~/.local/bin && install -m 0755 {asset} \
                 ~/.local/bin/ouro",
                directory.display()
            ),
        ));
    }

    let _ = writeln!(out, "  asset     {asset}");
    let _ = writeln!(out, "  target    {}", target.display());

    let staged = staging_path(&target);
    let _ = fs::remove_file(&staged);

    let outcome = install(source, &asset, entry, &staged, &target, out);

    if outcome.is_err() {
        let _ = fs::remove_file(&staged);
    }

    outcome?;

    let _ = writeln!(out, "updated {running} -> {release}");

    Ok(Outcome::Updated {
        running,
        release,
        path: target,
    })
}

fn install(
    source: &Source,
    asset: &str,
    entry: &SumEntry,
    staged: &Path,
    target: &Path,
    out: &mut dyn Write,
) -> std::result::Result<(), Refusal> {
    // Straight into the directory the rename will happen in, so the new binary is never
    // copied across a filesystem boundary after it has been verified.
    let length = source
        .fetch_to(asset, staged, ASSET_CAP, ASSET_TIMEOUT)
        .map_err(|error| {
            Refusal::new(
                Exit::TRANSPORT,
                format!("ouro update: could not fetch {asset}: {error:#}"),
            )
        })?;

    let digest = sha256_of_file(staged).map_err(|error| {
        Refusal::new(
            Exit::TRANSPORT,
            format!("ouro update: could not read the download back: {error:#}"),
        )
    })?;

    if digest != entry.digest {
        return Err(Refusal::new(
            Exit::VERIFICATION,
            format!(
                "ouro update: {asset} hashes to {} and the signed {SUMS_NAME} says {}. \
                 The download does not match what the release key signed — refusing, and \
                 {} is untouched.",
                hex(&digest),
                hex(&entry.digest),
                target.display()
            ),
        ));
    }

    let mut head = [0_u8; 4];
    let read = File::open(staged)
        .and_then(|mut file| file.read(&mut head))
        .unwrap_or(0);

    if !looks_executable(&head[..read]) {
        return Err(Refusal::new(
            Exit::VERIFICATION,
            format!(
                "ouro update: {asset} matched its signed digest but does not start like an \
                 executable for this platform. That is a release built wrong, not a \
                 download gone wrong — refusing."
            ),
        ));
    }

    let _ = writeln!(
        out,
        "  sha256    ok, {length} bytes match the signed {SUMS_NAME} entry"
    );

    publish(staged, target)
        .map_err(|error| Refusal::new(Exit::NOT_WRITABLE, format!("ouro update: {error:#}")))?;

    Ok(())
}

/// The file this process was started from, with symlinks resolved.
///
/// Resolved because the thing that has to be replaced atomically is the real file: a
/// `~/.local/bin/ouro` symlink into a read-only prefix is a case to refuse clearly, not
/// one to half-perform by swapping the link.
fn installed_path() -> Result<PathBuf> {
    let path = std::env::current_exe().context("finding this binary on disk")?;

    fs::canonicalize(&path).with_context(|| format!("resolving {}", path.display()))
}

fn writable(directory: &Path) -> bool {
    // Asking the filesystem beats reasoning about uid, gid, supplementary groups, ACLs,
    // and read-only mounts — all of which can make a mode look permissive and still
    // refuse the write.
    let probe = directory.join(format!(".ouro-update-probe-{}", std::process::id()));

    match OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// A private directory for the two small files that are checked before anything is
/// installed.
///
/// Created exclusively rather than with `create_dir_all`, and never after a
/// `remove_dir_all` of the same name: adopting a directory that was already there would
/// mean writing through whatever symlinks somebody else had put in it, and this runs in
/// a world-writable `/tmp`. The name is unique per *call*, not per process, so two
/// updates in one process — which is what a test suite is — cannot collect each other's
/// downloads.
fn scratch_directory() -> Result<PathBuf> {
    static SCRATCH: AtomicU32 = AtomicU32::new(0);

    let root = std::env::temp_dir();

    for _ in 0..64 {
        let directory = root.join(format!(
            "ouro-update-{}-{}",
            std::process::id(),
            SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));

        match fs::create_dir(&directory) {
            Ok(()) => {
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("restricting {}", directory.display()))?;

                return Ok(directory);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", directory.display()))
            }
        }
    }

    Err(anyhow!(
        "could not create a private scratch directory under {}",
        root.display()
    ))
}

/// The entry point `main` calls: prints the page on stdout, the refusal on stderr, and
/// carries the exit code out as an error the way `ouro run` does.
pub fn main(options: &Options) -> Result<()> {
    if let Some(problem) = key_is_present_but_unusable() {
        eprintln!(
            "ouro update: the release public key compiled into this binary is unusable: \
             {problem}.\nThat is a broken build rather than a missing key — dist/release.pub \
             holds something, and it is not a minisign Ed25519 public key. Nothing was \
             downloaded and nothing was verified."
        );

        return Err(Exit::NO_KEY.into());
    }

    let key = release_public_key();
    let mut out = std::io::stdout();

    match perform(options, key.as_ref(), &mut out) {
        Ok(outcome) => {
            let exit = outcome.exit();

            if exit == Exit::OK {
                Ok(())
            } else {
                Err(exit.into())
            }
        }
        Err(refusal) => {
            eprintln!("{}", refusal.message);
            Err(refusal.exit.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_order_by_semver_including_prereleases() {
        let order = [
            "0.1.0",
            "0.2.0-alpha",
            "0.2.0-alpha.1",
            "0.2.0-alpha.2",
            "0.2.0-beta",
            "0.2.0-rc.1",
            "0.2.0",
            "0.2.1",
            "1.0.0",
            "10.0.0",
        ];

        for pair in order.windows(2) {
            let left = Version::parse(pair[0]).expect(pair[0]);
            let right = Version::parse(pair[1]).expect(pair[1]);

            assert!(left < right, "{} should sort before {}", pair[0], pair[1]);
        }
    }

    #[test]
    fn numeric_prerelease_identifiers_do_not_compare_as_text() {
        let nine = Version::parse("1.0.0-rc.9").unwrap();
        let ten = Version::parse("1.0.0-rc.10").unwrap();

        assert!(nine < ten, "rc.9 must precede rc.10, not follow it");
    }

    #[test]
    fn build_metadata_is_not_a_different_release() {
        assert_eq!(
            Version::parse("1.2.3+build.7").unwrap(),
            Version::parse("1.2.3").unwrap()
        );
    }

    #[test]
    fn malformed_versions_are_refused_rather_than_guessed() {
        for text in [
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            "1.2.x",
            "",
            "1.2.3-",
            "1.0.0-a..b",
        ] {
            assert!(Version::parse(text).is_none(), "{text:?} parsed");
        }
    }

    #[test]
    fn the_crate_version_round_trips() {
        assert_eq!(running_version().to_string(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn triples_cover_the_release_matrix_and_nothing_else() {
        assert_eq!(triple_for("macos", "aarch64"), Some("aarch64-apple-darwin"));
        assert_eq!(triple_for("macos", "x86_64"), Some("x86_64-apple-darwin"));
        assert_eq!(
            triple_for("linux", "x86_64"),
            Some("x86_64-unknown-linux-gnu")
        );
        assert_eq!(
            triple_for("linux", "aarch64"),
            Some("aarch64-unknown-linux-gnu")
        );

        assert_eq!(triple_for("windows", "x86_64"), None);
        assert_eq!(triple_for("linux", "riscv64"), None);
        assert_eq!(triple_for("freebsd", "x86_64"), None);

        let host = host_triple().expect("this test runs on a release platform");
        assert!(TRIPLES.contains(&host));
    }

    #[test]
    fn asset_names_round_trip_through_their_version() {
        let version = Version::parse("0.2.0-rc.1").unwrap();
        let name = asset_name(&version, "aarch64-apple-darwin");

        assert_eq!(name, "ouro-0.2.0-rc.1-aarch64-apple-darwin");
        assert_eq!(version_of_asset(&name), Some(version));

        assert_eq!(version_of_asset("SHA256SUMS"), None);
        assert_eq!(version_of_asset("ouro-0.2.0-sparc-solaris"), None);
    }

    fn sums_line(digest: u8, name: &str) -> String {
        format!("{}  {name}\n", hex(&[digest; 32]))
    }

    #[test]
    fn the_sums_parser_reads_both_sha256sum_spellings() {
        let star = hex(&[0xbb; 32]);
        let text = format!(
            "{}{star} *ouro-1.0.0-x86_64-unknown-linux-gnu\n",
            sums_line(0xaa, "ouro-1.0.0-aarch64-apple-darwin"),
        );

        let entries = parse_sums(&text).expect("both spellings");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].digest, [0xaa; 32]);
        assert_eq!(entries[1].name, "ouro-1.0.0-x86_64-unknown-linux-gnu");
        assert_eq!(release_version(&entries).unwrap().to_string(), "1.0.0");
    }

    #[test]
    fn the_sums_parser_refuses_ambiguity_rather_than_resolving_it() {
        let duplicate = format!(
            "{}{}",
            sums_line(0xaa, "ouro-1.0.0-aarch64-apple-darwin"),
            sums_line(0xbb, "ouro-1.0.0-aarch64-apple-darwin")
        );

        let error = parse_sums(&duplicate).expect_err("two digests for one name");
        assert!(
            error.to_string().contains("two different digests"),
            "{error}"
        );

        let repeated = sums_line(0xaa, "ouro-1.0.0-aarch64-apple-darwin").repeat(2);
        assert!(
            parse_sums(&repeated).is_err(),
            "an exact repeat is still ambiguous"
        );

        for bad in [
            "not a digest  ouro-1.0.0-aarch64-apple-darwin\n",
            "aa  ouro-1.0.0-aarch64-apple-darwin\n",
            "ouro-1.0.0-aarch64-apple-darwin\n",
            "",
        ] {
            assert!(parse_sums(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn the_sums_parser_refuses_a_name_that_is_really_a_path() {
        for name in ["../ouro", "bin/ouro", ".ssh"] {
            let error = parse_sums(&sums_line(0xaa, name)).expect_err(name);
            assert!(error.to_string().contains("path"), "{error}");
        }
    }

    #[test]
    fn a_manifest_naming_two_versions_is_refused() {
        let text = format!(
            "{}{}",
            sums_line(0xaa, "ouro-1.0.0-aarch64-apple-darwin"),
            sums_line(0xbb, "ouro-2.0.0-x86_64-unknown-linux-gnu")
        );

        let entries = parse_sums(&text).expect("two well-formed lines");
        let error = release_version(&entries).expect_err("two versions");

        assert!(
            error.to_string().contains("one release, one version"),
            "{error}"
        );
    }

    #[test]
    fn blake2b512_matches_the_published_vectors() {
        // RFC 7693 Appendix A and the BLAKE2 reference vectors. Checked here because a
        // prehashed minisign signature is a signature over exactly this digest, so a
        // wrong hash would reject every signature the pipeline makes.
        assert_eq!(
            hex(&blake2b512(b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );

        assert_eq!(
            hex(&blake2b512(b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    // -------------------------------------------------------------------------------
    // A test key pair, made here and never committed.
    // -------------------------------------------------------------------------------

    pub(crate) struct TestKey {
        pair: ring::signature::Ed25519KeyPair,
        key_id: [u8; 8],
        public: [u8; 32],
    }

    impl TestKey {
        pub(crate) fn new(seed: u8) -> TestKey {
            use ring::signature::KeyPair;

            let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
                .expect("a 32-byte seed is a key");

            let mut public = [0_u8; 32];
            public.copy_from_slice(pair.public_key().as_ref());

            TestKey {
                pair,
                key_id: [seed, 1, 2, 3, 4, 5, 6, 7],
                public,
            }
        }

        pub(crate) fn public_key_file(&self) -> String {
            let mut bytes = Vec::with_capacity(42);
            bytes.extend_from_slice(&ALG_ED25519);
            bytes.extend_from_slice(&self.key_id);
            bytes.extend_from_slice(&self.public);

            format!(
                "untrusted comment: minisign public key {}\n{}\n",
                PublicKey {
                    key_id: self.key_id,
                    key: self.public
                }
                .id(),
                BASE64.encode(&bytes)
            )
        }

        /// Writes a `.minisig` the way `minisign -S` does.
        pub(crate) fn sign(&self, message: &[u8], prehashed: bool, comment: &str) -> String {
            let algorithm = if prehashed {
                ALG_ED25519_PREHASHED
            } else {
                ALG_ED25519
            };

            let signed = if prehashed {
                blake2b512(message).to_vec()
            } else {
                message.to_vec()
            };

            let signature = self.pair.sign(&signed);

            let mut line = Vec::with_capacity(74);
            line.extend_from_slice(&algorithm);
            line.extend_from_slice(&self.key_id);
            line.extend_from_slice(signature.as_ref());

            let mut global = Vec::new();
            global.extend_from_slice(signature.as_ref());
            global.extend_from_slice(comment.as_bytes());

            let global = self.pair.sign(&global);

            format!(
                "untrusted comment: signature from a test key\n{}\ntrusted comment: {comment}\n{}\n",
                BASE64.encode(&line),
                BASE64.encode(global.as_ref())
            )
        }
    }

    #[test]
    fn a_signature_over_the_sums_file_verifies_in_both_minisign_modes() {
        let key = TestKey::new(7);
        let public = PublicKey::parse(&key.public_key_file()).expect("a public key file");
        let message = b"whatever the release published";

        for prehashed in [false, true] {
            let text = key.sign(message, prehashed, "timestamp:1 file:SHA256SUMS");
            let signature = Signature::parse(&text).expect("a signature file");

            let trusted = verify(&public, &signature, message).expect("a valid signature");

            assert_eq!(trusted, "timestamp:1 file:SHA256SUMS");
        }
    }

    #[test]
    fn a_tampered_message_is_refused() {
        let key = TestKey::new(9);
        let public = PublicKey::parse(&key.public_key_file()).unwrap();
        let text = key.sign(b"the real sums", false, "t");
        let signature = Signature::parse(&text).unwrap();

        let error = verify(&public, &signature, b"the fake sums").expect_err("a refusal");

        assert!(error.to_string().contains("were not signed by"), "{error}");
    }

    #[test]
    fn a_signature_by_another_key_is_refused_by_key_id_before_anything_else() {
        let ours = TestKey::new(1);
        let theirs = TestKey::new(2);

        let public = PublicKey::parse(&ours.public_key_file()).unwrap();
        let text = theirs.sign(b"sums", false, "t");
        let signature = Signature::parse(&text).unwrap();

        let error = verify(&public, &signature, b"sums").expect_err("a refusal");

        assert!(
            error.to_string().contains("this build trusts key"),
            "{error}"
        );
    }

    /// Substituting one valid signature for another under the same key must not let the
    /// trusted comment come along for the ride.
    #[test]
    fn an_unauthenticated_trusted_comment_is_refused() {
        let key = TestKey::new(3);
        let public = PublicKey::parse(&key.public_key_file()).unwrap();

        let text = key.sign(b"sums", false, "timestamp:1 file:SHA256SUMS");
        let forged = text.replace(
            "trusted comment: timestamp:1 file:SHA256SUMS",
            "trusted comment: signed by the Ouroboros project, honest",
        );

        let signature = Signature::parse(&forged).unwrap();
        let error = verify(&public, &signature, b"sums").expect_err("a refusal");

        assert!(error.to_string().contains("not covered by key"), "{error}");
    }

    #[test]
    fn malformed_signature_files_are_refused() {
        let key = TestKey::new(4);
        let good = key.sign(b"sums", false, "t");

        assert!(Signature::parse("").is_err());
        assert!(Signature::parse("untrusted comment: x\n").is_err());
        assert!(Signature::parse(&good.replace("trusted comment: ", "comment: ")).is_err());

        let lines: Vec<&str> = good.lines().collect();
        let truncated = format!("{}\n{}\n", lines[0], &lines[1][..20]);
        assert!(Signature::parse(&truncated).is_err(), "a short signature");
    }

    #[test]
    fn the_committed_public_key_is_either_a_key_or_plainly_absent() {
        // The tree ships an unprovisioned dist/release.pub, and this asserts the two
        // states are the only ones: a file that parses to a key, or a refusal that says
        // there is no key. Nothing in between is allowed to look like verification.
        match PublicKey::parse(RELEASE_PUBLIC_KEY_SOURCE) {
            Ok(key) => assert_eq!(key.id().len(), 16, "a key id is 16 hex digits"),
            Err(error) => assert!(
                error.to_string().contains("no minisign public key"),
                "an unprovisioned key must say so: {error}"
            ),
        }
    }

    #[test]
    fn a_public_key_file_must_be_ed25519_and_the_right_length() {
        let short = BASE64.encode(b"Ed12345678");
        assert!(PublicKey::parse(&format!("untrusted comment: x\n{short}\n")).is_err());

        let mut bytes = vec![b'R', b'S'];
        bytes.extend_from_slice(&[0_u8; 40]);
        let wrong_algorithm = BASE64.encode(&bytes);
        let error =
            PublicKey::parse(&format!("untrusted comment: x\n{wrong_algorithm}\n")).unwrap_err();
        assert!(error.to_string().contains("Ed25519"), "{error}");
    }

    #[test]
    fn sources_are_read_from_their_scheme() {
        assert_eq!(
            Source::parse("file:///tmp/release").unwrap(),
            Source::Directory(PathBuf::from("/tmp/release"))
        );
        assert_eq!(
            Source::parse("/tmp/release").unwrap(),
            Source::Directory(PathBuf::from("/tmp/release"))
        );
        assert_eq!(
            Source::parse("https://example.invalid/d/").unwrap(),
            Source::Url("https://example.invalid/d".into())
        );

        assert!(Source::parse("file://host/path").is_err());
        assert!(Source::parse("ftp://example.invalid/").is_err());

        assert!(Source::parse("https://x.invalid")
            .unwrap()
            .transport_is_authenticated());
        assert!(!Source::parse("http://x.invalid")
            .unwrap()
            .transport_is_authenticated());
    }

    #[test]
    fn an_asset_name_cannot_escape_the_release_directory() {
        let source = Source::Directory(PathBuf::from("/tmp"));
        let scratch = std::env::temp_dir();

        for name in ["../etc/passwd", "a/b", "..\\b"] {
            assert!(source.fetch_bytes(name, 16, &scratch).is_err(), "{name}");
        }
    }

    #[test]
    fn only_a_platform_executable_passes_the_shape_check() {
        assert!(looks_executable(b"\x7fELF\x02"));
        assert!(looks_executable(&[0xcf, 0xfa, 0xed, 0xfe]));
        assert!(!looks_executable(b"<!DOCTYPE html>"));
        assert!(!looks_executable(b"#!/"));
        assert!(!looks_executable(b""));
    }

    #[test]
    fn package_managed_installs_are_named_and_refused() {
        assert_eq!(
            managed_by(Path::new("/opt/homebrew/Cellar/ouro/0.1.0/bin/ouro")),
            Some("Homebrew")
        );
        assert_eq!(
            managed_by(Path::new("/nix/store/abc-ouro/bin/ouro")),
            Some("Nix")
        );
        assert_eq!(managed_by(Path::new("/home/x/.local/bin/ouro")), None);
    }

    #[test]
    fn staging_happens_beside_the_target_so_the_rename_stays_on_one_filesystem() {
        let staged = staging_path(Path::new("/home/x/.local/bin/ouro"));

        assert_eq!(staged.parent(), Some(Path::new("/home/x/.local/bin")));
        assert!(staged
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".ouro.update-"));
    }

    #[test]
    fn a_staged_file_is_renamed_over_the_target_and_keeps_its_mode() {
        let directory = std::env::temp_dir().join(format!(
            "ouro-update-replace-{}-{}",
            std::process::id(),
            line!()
        ));
        fs::create_dir_all(&directory).unwrap();

        let target = directory.join("ouro");
        fs::write(&target, b"the old binary").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();

        let staged = staging_path(&target);
        stage(&staged, b"the new binary").unwrap();
        publish(&staged, &target).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"the new binary");
        assert!(
            !staged.exists(),
            "the staged copy is consumed by the rename"
        );
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o700,
            "a private install must not become world-executable by updating"
        );

        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn a_binary_without_a_release_key_refuses_every_path() {
        for options in [
            Options::default(),
            Options {
                check: true,
                ..Options::default()
            },
        ] {
            let mut out = Vec::new();
            let refusal = perform(&options, None, &mut out).expect_err("a refusal");

            assert_eq!(refusal.exit, Exit::NO_KEY);
            assert!(
                refusal.message.contains("no release signing key"),
                "{}",
                refusal.message
            );
            assert!(
                out.is_empty(),
                "nothing is reported before the key is checked"
            );
        }
    }

    /// The committed tree is unprovisioned, so this must report *no* problem: a build
    /// that confused "unprovisioned" with "corrupt" would send every reader to the wrong
    /// page.
    #[test]
    fn an_unprovisioned_key_is_not_reported_as_a_broken_one() {
        match key_line(RELEASE_PUBLIC_KEY_SOURCE) {
            None => assert_eq!(key_is_present_but_unusable(), None),
            Some(_) => assert_eq!(
                key_is_present_but_unusable(),
                None,
                "a provisioned dist/release.pub must parse"
            ),
        }

        // And a file that holds something unparseable is reported as broken, not absent.
        assert!(PublicKey::parse("untrusted comment: x\nnot base64 at all!!\n").is_err());
        assert!(key_line("untrusted comment: x\nnot base64 at all!!\n").is_some());
    }

    #[test]
    fn writability_is_probed_rather_than_inferred_from_a_mode() {
        assert!(writable(&std::env::temp_dir()));
        assert!(!writable(Path::new(
            "/proc/self/definitely-not-a-directory"
        )));
    }
}
