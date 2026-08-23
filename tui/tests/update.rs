//! `ouro update` end to end, against a release directory this test builds and signs.
//!
//! Nothing here touches the network, and nothing here touches an install outside its own
//! scratch directory: the release lives in a temp directory, the "installed binary" is a
//! file in another one, and the signing key is generated per test and never written
//! anywhere it could be mistaken for the project's.
//!
//! The signing side is deliberately re-implemented from the format rather than shared
//! with the verifier, so a mistake in one does not cancel out in the other. What it
//! cannot catch is a shared *misreading of minisign's format* — for that, see the
//! `minisign` interoperability test at the bottom, which runs only where the reference
//! implementation is installed, and the honest gap noted in `docs/DISTRIBUTION.md`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ouro::update::{self, Exit, Options, Outcome, PublicKey};
use ring::signature::{Ed25519KeyPair, KeyPair};

static SCRATCH: AtomicU32 = AtomicU32::new(0);

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "ouro-update-test-{name}-{}-{}",
        std::process::id(),
        SCRATCH.fetch_add(1, Ordering::Relaxed)
    ));

    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("a scratch directory");
    directory
}

/// A throwaway release key. `from_seed_unchecked` keeps it deterministic per test, and
/// the private half exists only for the length of the process.
struct Signer {
    pair: Ed25519KeyPair,
    key_id: [u8; 8],
    public: [u8; 32],
}

impl Signer {
    fn new(seed: u8) -> Signer {
        let pair =
            Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("a 32-byte seed is a key");

        let mut public = [0_u8; 32];
        public.copy_from_slice(pair.public_key().as_ref());

        Signer {
            pair,
            key_id: [seed, 0xde, 0xad, 0xbe, 0xef, 1, 2, 3],
            public,
        }
    }

    /// The two lines `minisign -G` writes into a `.pub`.
    fn public_key_file(&self) -> String {
        let mut bytes = Vec::with_capacity(42);
        bytes.extend_from_slice(b"Ed");
        bytes.extend_from_slice(&self.key_id);
        bytes.extend_from_slice(&self.public);

        format!(
            "untrusted comment: minisign public key\n{}\n",
            BASE64.encode(&bytes)
        )
    }

    fn key(&self) -> PublicKey {
        PublicKey::parse(&self.public_key_file()).expect("a public key file")
    }

    /// The four lines `minisign -S` writes into a `.minisig`, in the prehashed form
    /// current releases of minisign produce by default.
    fn sign(&self, message: &[u8]) -> String {
        use blake2::digest::consts::U64;
        use blake2::{Blake2b, Digest};

        let mut hasher = Blake2b::<U64>::new();
        hasher.update(message);
        let prehashed = hasher.finalize();

        let signature = self.pair.sign(&prehashed);
        let comment = "timestamp:1766000000\tfile:SHA256SUMS\thashed";

        let mut line = Vec::with_capacity(74);
        line.extend_from_slice(b"ED");
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

/// Bytes that pass the "does this start like an executable" shape check on this host.
fn fake_binary(marker: &str) -> Vec<u8> {
    let mut bytes = match std::env::consts::OS {
        "macos" => vec![0xcf, 0xfa, 0xed, 0xfe],
        _ => b"\x7fELF".to_vec(),
    };

    bytes.extend_from_slice(marker.as_bytes());
    bytes.resize(4096, 0x41);
    bytes
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Writes a release directory: one asset for this host triple, a `SHA256SUMS` naming it,
/// and a signature over that file.
fn release(directory: &Path, signer: &Signer, version: &str, marker: &str) -> Vec<u8> {
    let triple = update::host_triple().expect("this test runs on a release platform");
    let bytes = fake_binary(marker);
    let asset = format!("ouro-{version}-{triple}");

    fs::write(directory.join(&asset), &bytes).unwrap();

    let sums = format!("{}  {asset}\n", sha256_hex(&bytes));
    fs::write(directory.join("SHA256SUMS"), &sums).unwrap();
    fs::write(
        directory.join("SHA256SUMS.minisig"),
        signer.sign(sums.as_bytes()),
    )
    .unwrap();

    bytes
}

/// An "installed binary" to be replaced, and its directory.
fn installed(directory: &Path) -> PathBuf {
    let path = directory.join("ouro");
    fs::write(&path, fake_binary("the installed one")).unwrap();

    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

    path
}

fn run(
    options: &Options,
    signer: &Signer,
    target: &Path,
) -> (std::result::Result<Outcome, update::Refusal>, String) {
    let mut out = Vec::new();
    let key = signer.key();
    let outcome = update::perform_into(options, Some(&key), Some(target), &mut out);

    (outcome, String::from_utf8(out).expect("printed text"))
}

// -------------------------------------------------------------------------------------
// The happy paths
// -------------------------------------------------------------------------------------

#[test]
fn check_reports_a_newer_release_and_downloads_no_asset() {
    let source = scratch("check-source");
    let home = scratch("check-home");
    let signer = Signer::new(11);

    release(&source, &signer, "9.9.9", "the new one");
    let target = installed(&home);
    let before = fs::read(&target).unwrap();

    let (outcome, printed) = run(
        &Options {
            check: true,
            from: Some(source.display().to_string()),
            ..Options::default()
        },
        &signer,
        &target,
    );

    let outcome = outcome.expect("a signed release");

    assert!(matches!(outcome, Outcome::Available { .. }), "{outcome:?}");
    assert_eq!(outcome.exit(), Exit::AVAILABLE);
    assert_eq!(outcome.exit().code(), 10);

    assert!(printed.contains("signature ok, Ed25519 key"), "{printed}");
    assert!(printed.contains("release   9.9.9"), "{printed}");
    assert!(printed.contains("an update is available"), "{printed}");

    assert_eq!(
        fs::read(&target).unwrap(),
        before,
        "--check installs nothing"
    );

    fs::remove_dir_all(&source).ok();
    fs::remove_dir_all(&home).ok();
}

#[test]
fn check_reports_no_update_when_the_release_is_not_newer() {
    let source = scratch("check-old-source");
    let home = scratch("check-old-home");
    let signer = Signer::new(12);

    release(&source, &signer, "0.0.1", "an older one");
    let target = installed(&home);

    let (outcome, printed) = run(
        &Options {
            check: true,
            from: Some(source.display().to_string()),
            ..Options::default()
        },
        &signer,
        &target,
    );

    let outcome = outcome.expect("a signed release");

    assert!(matches!(outcome, Outcome::Current { .. }), "{outcome:?}");
    assert_eq!(outcome.exit().code(), 0);
    assert!(printed.contains("no update"), "{printed}");

    fs::remove_dir_all(&source).ok();
    fs::remove_dir_all(&home).ok();
}

#[test]
fn a_verified_release_replaces_the_installed_binary_atomically() {
    let source = scratch("install-source");
    let home = scratch("install-home");
    let signer = Signer::new(13);

    let published = release(&source, &signer, "9.9.9", "the new one");
    let target = installed(&home);

    let (outcome, printed) = run(
        &Options {
            from: Some(source.display().to_string()),
            ..Options::default()
        },
        &signer,
        &target,
    );

    let outcome = outcome.expect("a signed release");

    assert!(matches!(outcome, Outcome::Updated { .. }), "{outcome:?}");
    assert_eq!(outcome.exit().code(), 0);

    assert!(printed.contains("signature ok"), "{printed}");
    assert!(
        printed.contains("sha256    ok") && printed.contains("match the signed SHA256SUMS entry"),
        "the two checks are reported separately: {printed}"
    );
    assert!(printed.contains("updated 0.1.0 -> 9.9.9"), "{printed}");

    assert_eq!(fs::read(&target).unwrap(), published);

    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o755
    );

    let leftovers: Vec<String> = fs::read_dir(&home)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != "ouro")
        .collect();

    assert!(leftovers.is_empty(), "staged files survived: {leftovers:?}");

    fs::remove_dir_all(&source).ok();
    fs::remove_dir_all(&home).ok();
}

#[test]
fn a_release_naming_the_running_version_installs_nothing() {
    let source = scratch("same-source");
    let home = scratch("same-home");
    let signer = Signer::new(14);

    release(&source, &signer, env!("CARGO_PKG_VERSION"), "identical");
    let target = installed(&home);
    let before = fs::read(&target).unwrap();

    let (outcome, printed) = run(
        &Options {
            from: Some(source.display().to_string()),
            ..Options::default()
        },
        &signer,
        &target,
    );

    assert!(
        matches!(
            outcome.expect("a signed release"),
            Outcome::AlreadyInstalled { .. }
        ),
        "{printed}"
    );
    assert_eq!(fs::read(&target).unwrap(), before);

    fs::remove_dir_all(&source).ok();
    fs::remove_dir_all(&home).ok();
}

// -------------------------------------------------------------------------------------
// The refusals. Each one asserts the installed binary is untouched, because a refusal
// that half-installed something is not a refusal.
// -------------------------------------------------------------------------------------

fn refuses(name: &str, seed: u8, damage: impl Fn(&Path), expected: Exit, phrase: &str) {
    let source = scratch(name);
    let home = scratch(&format!("{name}-home"));
    let signer = Signer::new(seed);

    release(&source, &signer, "9.9.9", "the new one");
    damage(&source);

    let target = installed(&home);
    let before = fs::read(&target).unwrap();

    let (outcome, _printed) = run(
        &Options {
            from: Some(source.display().to_string()),
            ..Options::default()
        },
        &signer,
        &target,
    );

    let refusal = outcome.expect_err("a refusal");

    assert_eq!(refusal.exit, expected, "{name}: {}", refusal.message);
    assert!(
        refusal.message.contains(phrase),
        "{name}: expected {phrase:?} in {:?}",
        refusal.message
    );
    assert_eq!(
        fs::read(&target).unwrap(),
        before,
        "{name}: a refusal left the installed binary changed"
    );

    let leftovers: Vec<String> = fs::read_dir(&home)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|entry| entry != "ouro")
        .collect();

    assert!(
        leftovers.is_empty(),
        "{name}: staged files survived {leftovers:?}"
    );

    fs::remove_dir_all(&source).ok();
    fs::remove_dir_all(&home).ok();
}

#[test]
fn a_tampered_signature_is_refused_and_nothing_is_installed() {
    refuses(
        "bad-signature",
        21,
        |source| {
            let path = source.join("SHA256SUMS.minisig");
            let text = fs::read_to_string(&path).unwrap();
            let mut lines: Vec<String> = text.lines().map(str::to_string).collect();

            // Flip one base64 character *inside the Ed25519 signature*. The key id
            // occupies bytes 2..10, which is roughly the first sixteen base64
            // characters, and a flip there would be caught by the key-id check instead —
            // a different refusal proving a different thing.
            let signature = &mut lines[1];
            let flipped = if signature.as_bytes()[40] == b'A' {
                "B"
            } else {
                "A"
            };
            signature.replace_range(40..41, flipped);

            fs::write(&path, lines.join("\n") + "\n").unwrap();
        },
        Exit::VERIFICATION,
        "not signed by the Ouroboros release key",
    );
}

#[test]
fn a_sums_file_edited_after_signing_is_refused() {
    refuses(
        "edited-sums",
        22,
        |source| {
            let path = source.join("SHA256SUMS");
            let text = fs::read_to_string(&path).unwrap();
            fs::write(&path, text.replace("9.9.9", "9.9.8")).unwrap();
        },
        Exit::VERIFICATION,
        "not signed by the Ouroboros release key",
    );
}

#[test]
fn an_asset_swapped_under_a_valid_signature_is_refused_by_its_digest() {
    refuses(
        "swapped-asset",
        23,
        |source| {
            let triple = update::host_triple().unwrap();
            let asset = source.join(format!("ouro-9.9.9-{triple}"));

            // The sums file and its signature still agree with each other. Only the
            // asset changed — which is exactly what the digest check is for.
            fs::write(&asset, fake_binary("something else entirely")).unwrap();
        },
        Exit::VERIFICATION,
        "does not match what the release key signed",
    );
}

#[test]
fn an_asset_that_is_not_an_executable_is_refused_even_when_the_digest_matches() {
    refuses(
        "html-asset",
        24,
        |source| {
            let triple = update::host_triple().unwrap();
            let asset = format!("ouro-9.9.9-{triple}");
            let page = b"<!DOCTYPE html><title>502 Bad Gateway</title>".to_vec();

            fs::write(source.join(&asset), &page).unwrap();

            // Re-sign, so the only thing wrong is the content itself.
            let sums = format!("{}  {asset}\n", sha256_hex(&page));
            fs::write(source.join("SHA256SUMS"), &sums).unwrap();
            fs::write(
                source.join("SHA256SUMS.minisig"),
                Signer::new(24).sign(sums.as_bytes()),
            )
            .unwrap();
        },
        Exit::VERIFICATION,
        "does not start like an executable",
    );
}

#[test]
fn a_signature_by_a_key_this_build_does_not_trust_is_refused() {
    refuses(
        "other-key",
        25,
        |source| {
            let sums = fs::read(source.join("SHA256SUMS")).unwrap();
            fs::write(
                source.join("SHA256SUMS.minisig"),
                Signer::new(99).sign(&sums),
            )
            .unwrap();
        },
        Exit::VERIFICATION,
        "this build trusts key",
    );
}

#[test]
fn a_missing_signature_is_a_transport_refusal_not_a_pass() {
    refuses(
        "no-signature",
        26,
        |source| {
            fs::remove_file(source.join("SHA256SUMS.minisig")).unwrap();
        },
        Exit::TRANSPORT,
        "could not fetch SHA256SUMS.minisig",
    );
}

#[test]
fn a_release_older_than_the_running_binary_is_refused_unless_asked_for() {
    let source = scratch("downgrade");
    let home = scratch("downgrade-home");
    let signer = Signer::new(27);

    let published = release(&source, &signer, "0.0.1", "the old one");
    let target = installed(&home);
    let before = fs::read(&target).unwrap();

    let options = Options {
        from: Some(source.display().to_string()),
        ..Options::default()
    };

    let refusal = run(&options, &signer, &target).0.expect_err("a refusal");

    assert_eq!(refusal.exit, Exit::DOWNGRADE);
    assert_eq!(refusal.exit.code(), 13);
    assert!(
        refusal.message.contains("--allow-downgrade"),
        "{}",
        refusal.message
    );
    assert_eq!(fs::read(&target).unwrap(), before);

    // And with the flag it is an ordinary install.
    let (outcome, _printed) = run(
        &Options {
            allow_downgrade: true,
            ..options
        },
        &signer,
        &target,
    );

    assert!(matches!(outcome.unwrap(), Outcome::Updated { .. }));
    assert_eq!(fs::read(&target).unwrap(), published);

    fs::remove_dir_all(&source).ok();
    fs::remove_dir_all(&home).ok();
}

#[test]
fn a_release_without_an_asset_for_this_platform_is_refused() {
    let source = scratch("no-asset");
    let home = scratch("no-asset-home");
    let signer = Signer::new(28);

    // A signed manifest for a platform that is definitely not this one.
    let other = update::TRIPLES
        .iter()
        .find(|triple| Some(**triple) != update::host_triple())
        .expect("four triples, one host");

    let asset = format!("ouro-9.9.9-{other}");
    let sums = format!("{}  {asset}\n", sha256_hex(b"not for you"));

    fs::write(source.join("SHA256SUMS"), &sums).unwrap();
    fs::write(
        source.join("SHA256SUMS.minisig"),
        signer.sign(sums.as_bytes()),
    )
    .unwrap();

    let target = installed(&home);
    let refusal = run(
        &Options {
            from: Some(source.display().to_string()),
            ..Options::default()
        },
        &signer,
        &target,
    )
    .0
    .expect_err("a refusal");

    assert_eq!(refusal.exit, Exit::NO_ASSET);
    assert_eq!(refusal.exit.code(), 16);

    fs::remove_dir_all(&source).ok();
    fs::remove_dir_all(&home).ok();
}

#[test]
fn a_source_that_does_not_exist_is_a_transport_refusal() {
    let home = scratch("missing-source-home");
    let target = installed(&home);
    let signer = Signer::new(29);

    let refusal = run(
        &Options {
            check: true,
            from: Some("/nonexistent/ouro-release-directory".into()),
            ..Options::default()
        },
        &signer,
        &target,
    )
    .0
    .expect_err("a refusal");

    assert_eq!(refusal.exit, Exit::TRANSPORT);
    assert_eq!(refusal.exit.code(), 15);

    fs::remove_dir_all(&home).ok();
}

#[test]
fn a_build_with_no_release_key_refuses_before_it_fetches_anything() {
    let home = scratch("no-key-home");
    let target = installed(&home);
    let mut out = Vec::new();

    let refusal = update::perform_into(
        &Options {
            check: true,
            from: Some("/nonexistent".into()),
            ..Options::default()
        },
        None,
        Some(&target),
        &mut out,
    )
    .expect_err("a refusal");

    assert_eq!(refusal.exit, Exit::NO_KEY);
    assert_eq!(refusal.exit.code(), 11);
    assert!(
        refusal
            .message
            .contains("Nothing was downloaded and nothing was verified"),
        "{}",
        refusal.message
    );

    fs::remove_dir_all(&home).ok();
}

// -------------------------------------------------------------------------------------
// The binary, as a person would run it
// -------------------------------------------------------------------------------------

#[test]
fn the_subcommand_exits_with_the_documented_code() {
    let source = scratch("cli-source");
    let signer = Signer::new(31);
    release(&source, &signer, "9.9.9", "the new one");

    let output = Command::new(env!("CARGO_BIN_EXE_ouro"))
        .arg("update")
        .arg("--check")
        .arg("--from")
        .arg(&source)
        .output()
        .expect("running ouro update --check");

    let code = output.status.code().expect("an exit code");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    match update::release_public_key() {
        // The tree ships an unprovisioned dist/release.pub, so this is the state the
        // suite normally runs in: the command refuses, says why, and prints nothing that
        // could be read as a verified answer.
        None => {
            assert_eq!(code, 11, "stdout: {stdout}\nstderr: {stderr}");
            assert!(
                stderr.contains("no release signing key"),
                "stderr: {stderr}"
            );
            assert!(
                !stdout.contains("9.9.9"),
                "an unverifiable version must not be reported: {stdout}"
            );
        }
        // A provisioned build refuses this fixture too — the test key is not the release
        // key — but for a different reason and with a different code.
        Some(key) => {
            assert_eq!(code, 12, "stdout: {stdout}\nstderr: {stderr}");
            assert!(stderr.contains(&key.id()), "stderr: {stderr}");
        }
    }

    fs::remove_dir_all(&source).ok();
}

#[test]
fn the_subcommand_is_documented_in_its_own_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_ouro"))
        .arg("update")
        .arg("--help")
        .output()
        .expect("running ouro update --help");

    let help = String::from_utf8_lossy(&output.stdout);

    for expected in [
        "--check",
        "--from",
        "--allow-downgrade",
        "Exit codes",
        "There is no `--channel`",
    ] {
        assert!(
            help.contains(expected),
            "{expected:?} missing from:\n{help}"
        );
    }

    assert!(
        !help.contains("--channel <"),
        "a channel flag would be inventing a release scheme this project does not have"
    );
}

// -------------------------------------------------------------------------------------
// Interoperability with the reference implementation, where it is installed
// -------------------------------------------------------------------------------------

/// Signs a fixture with the real `minisign` and verifies it with this crate's verifier.
///
/// Skipped — loudly, in the test log — where `minisign` is not on PATH, which is the
/// case on the machine this was written on. It is the only check that can catch this
/// crate and its own test signer sharing a misreading of minisign's byte layout, so
/// `docs/DISTRIBUTION.md` names its absence as an open gap rather than pretending the
/// format was confirmed.
#[test]
fn a_real_minisign_signature_verifies() {
    let Some(minisign) = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join("minisign"))
            .find(|candidate| candidate.is_file())
    }) else {
        eprintln!(
            "SKIPPED a_real_minisign_signature_verifies: minisign is not on PATH, so this \
             crate's reading of the .minisig format is unconfirmed against the reference \
             implementation (docs/DISTRIBUTION.md, open gaps)"
        );
        return;
    };

    let directory = scratch("minisign-interop");
    let secret = directory.join("key.sec");
    let public = directory.join("key.pub");
    let message = directory.join("SHA256SUMS");

    fs::write(
        &message,
        "0".repeat(64) + "  ouro-9.9.9-x86_64-unknown-linux-gnu\n",
    )
    .unwrap();

    let generated = Command::new(&minisign)
        .args(["-G", "-W", "-p"])
        .arg(&public)
        .arg("-s")
        .arg(&secret)
        .output()
        .expect("minisign -G");

    assert!(
        generated.status.success(),
        "minisign -G failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );

    let signed = Command::new(&minisign)
        .arg("-S")
        .arg("-s")
        .arg(&secret)
        .arg("-m")
        .arg(&message)
        .output()
        .expect("minisign -S");

    assert!(
        signed.status.success(),
        "minisign -S failed: {}",
        String::from_utf8_lossy(&signed.stderr)
    );

    let key = PublicKey::parse(&fs::read_to_string(&public).unwrap()).expect("minisign's own .pub");
    let signature_text = fs::read_to_string(directory.join("SHA256SUMS.minisig")).unwrap();
    let signature = update::Signature::parse(&signature_text).expect("minisign's own .minisig");

    update::verify(&key, &signature, &fs::read(&message).unwrap())
        .expect("a signature the reference implementation made");

    fs::remove_dir_all(&directory).ok();
}
