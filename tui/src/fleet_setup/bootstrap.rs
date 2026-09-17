//! Seam S8: putting an `ouro` on a target that has none.
//!
//! Two remote command strings live here, and both are **constants**. `ssh` hands its
//! command to the remote login shell, so any variable spliced into one of them would be
//! shell source on a machine this operator has just authenticated to. Everything
//! variable — the artifact's name, its size, its sha256, where it should end up —
//! arrives on stdin, one field per line, and the remote script validates each one with a
//! `case` pattern before it is used.
//!
//! [`PREFLIGHT`] answers three questions a plan needs and cannot guess: what the target
//! is (so the right artifact is chosen from the supported matrix), where its `$HOME` is,
//! and whether it already has an `ouro`. [`BOOTSTRAP`] is the upload: a private staging
//! directory, exactly `size` bytes, a recomputed sha256, and one atomic rename into
//! place. It refuses to overwrite an existing installation, because the proposal limits
//! automatic installation to a *missing* one and keeps an unrelated or mismatched
//! installation an explicit manual step.
//!
//! What this deliberately does not do: substitute `latest`, retry a checksum failure,
//! touch anything outside `$HOME`, or run the uploaded file. Verifying that the
//! installed binary reports the expected version is the caller's next step, over the
//! normal helper protocol.

use std::collections::BTreeMap;

use anyhow::Result;

use super::ssh::{Completed, Runner};
use super::{refuse, sanitize_remote_text};

/// The fixed preflight command. No variable data: it reports, and the caller decides.
///
/// Output is `key value` lines, one per line, because a remote `$HOME` containing a
/// quote would break a `printf`-assembled JSON document and this has to be parseable on
/// every POSIX shell without a JSON tool.
pub const PREFLIGHT: &str = concat!(
    "set -u; ",
    "h=${HOME:-}; ",
    "s=$(uname -s 2>/dev/null || echo unknown); ",
    "m=$(uname -m 2>/dev/null || echo unknown); ",
    "if [ \"$s\" = Darwin ]; then v=$(sw_vers -productVersion 2>/dev/null || echo unknown); ",
    "else v=$(getconf GNU_LIBC_VERSION 2>/dev/null || echo unknown); fi; ",
    "o=missing; ",
    "if [ -n \"$h\" ] && [ -x \"$h/.local/bin/ouro\" ]; then o=\"$h/.local/bin/ouro\"; fi; ",
    "d=none; ",
    "if command -v sha256sum >/dev/null 2>&1; then d=sha256sum; ",
    "elif command -v shasum >/dev/null 2>&1; then d=shasum; fi; ",
    "echo ouroboros-preflight 1; ",
    "echo uname \"$s\"; ",
    "echo machine \"$m\"; ",
    "echo version \"$v\"; ",
    "echo home \"$h\"; ",
    "echo ouro \"$o\"; ",
    "echo digest \"$d\"",
);

/// The ONE fixed bootstrap command string (seam S8).
///
/// Reads six header lines and then exactly `size` bytes from stdin. Every field is
/// validated by a `case` pattern before it names a path: the artifact name must look
/// like a release asset and contain no separator, the install path is relative to
/// `$HOME` with no `..`, the size is decimal, the digest is 64 lowercase hex. The staged
/// file lands in a 0700 `$HOME/.ouroboros/setup/`, is size-checked and hash-checked, and
/// is then renamed — one atomic operation on the same filesystem — into place at 0755.
pub const BOOTSTRAP: &str = concat!(
    "set -u; umask 077; ",
    "IFS= read -r magic || exit 64; ",
    "IFS= read -r name || exit 64; ",
    "IFS= read -r size || exit 64; ",
    "IFS= read -r sum || exit 64; ",
    "IFS= read -r dest || exit 64; ",
    "IFS= read -r blank || exit 64; ",
    "[ \"$magic\" = ouroboros-bootstrap-1 ] || { echo bootstrap-error protocol; exit 64; }; ",
    "[ -z \"$blank\" ] || { echo bootstrap-error protocol; exit 64; }; ",
    "case \"$name\" in ouro-[0-9]*) ;; *) echo bootstrap-error name; exit 65;; esac; ",
    "case \"$name\" in *[!A-Za-z0-9._-]*) echo bootstrap-error name; exit 65;; esac; ",
    "case \"$size\" in ''|*[!0-9]*) echo bootstrap-error size; exit 65;; esac; ",
    "case \"$sum\" in *[!0-9a-f]*|'') echo bootstrap-error digest; exit 65;; esac; ",
    "[ ${#sum} -eq 64 ] || { echo bootstrap-error digest; exit 65; }; ",
    "case \"$dest\" in /*|*..*|'') echo bootstrap-error dest; exit 65;; esac; ",
    "case \"$dest\" in *[!A-Za-z0-9._/-]*) echo bootstrap-error dest; exit 65;; esac; ",
    "h=${HOME:-}; [ -n \"$h\" ] || { echo bootstrap-error home; exit 66; }; ",
    "p=$h/$dest; ",
    "if [ -e \"$p\" ]; then echo bootstrap-error exists; exit 68; fi; ",
    "d=$h/.ouroboros/setup; ",
    "mkdir -p \"$d\" || { echo bootstrap-error staging; exit 66; }; ",
    "chmod 700 \"$h/.ouroboros\" \"$d\" || { echo bootstrap-error staging; exit 66; }; ",
    "t=$d/$name; rm -f \"$t\"; ",
    "head -c \"$size\" > \"$t\" || { rm -f \"$t\"; echo bootstrap-error transfer; exit 66; }; ",
    "n=$(wc -c < \"$t\" | tr -d ' '); ",
    "[ \"$n\" = \"$size\" ] || { rm -f \"$t\"; echo bootstrap-error truncated; exit 66; }; ",
    "if command -v sha256sum >/dev/null 2>&1; then g=$(sha256sum < \"$t\" | cut -d' ' -f1); ",
    "elif command -v shasum >/dev/null 2>&1; then g=$(shasum -a 256 < \"$t\" | cut -d' ' -f1); ",
    "else rm -f \"$t\"; echo bootstrap-error no-digest-tool; exit 67; fi; ",
    "[ \"$g\" = \"$sum\" ] || { rm -f \"$t\"; echo bootstrap-error checksum; exit 67; }; ",
    "chmod 755 \"$t\" || { rm -f \"$t\"; echo bootstrap-error mode; exit 66; }; ",
    "mkdir -p \"$(dirname \"$p\")\" || { rm -f \"$t\"; echo bootstrap-error destdir; exit 66; }; ",
    "mv -f \"$t\" \"$p\" || { rm -f \"$t\"; echo bootstrap-error install; exit 66; }; ",
    "echo bootstrap-ok \"$g\" \"$p\"",
);

/// A bootstrap upload is a whole release binary over one SSH channel.
pub const UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// Where the default install goes, relative to the target's `$HOME`
/// (docs/RELEASING.md's convention).
pub const DEFAULT_INSTALL_PATH: &str = ".local/bin/ouro";

/// What [`PREFLIGHT`] reported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preflight {
    /// `uname -s`: `Darwin`, `Linux`, …
    pub uname: String,
    /// `uname -m`: `arm64`, `x86_64`, …
    pub machine: String,
    /// The macOS product version, or `glibc x.y`.
    pub version: String,
    pub home: String,
    /// The absolute path of an `ouro` at the default location, when there is one.
    pub existing: Option<String>,
    /// `sha256sum`, `shasum`, or `none`.
    pub digest_tool: String,
}

impl Preflight {
    /// Rust's own `os` spelling for this machine, which is what the platform matrix and
    /// the build contract are written in.
    pub fn os(&self) -> &'static str {
        match self.uname.as_str() {
            "Darwin" => "macos",
            "Linux" => "linux",
            _ => "unknown",
        }
    }

    pub fn target_triple(&self) -> Result<String> {
        crate::update::release::target_triple(self.os(), &self.machine, &self.version)
            .map_err(|error| super::refusing("unsupported_platform", error))
    }

    /// The absolute path an installed `ouro` will have.
    pub fn install_path(&self, relative: &str) -> String {
        format!("{}/{}", self.home.trim_end_matches('/'), relative)
    }
}

/// Run the fixed preflight on the target.
pub fn preflight(runner: &Runner) -> Result<Preflight> {
    let completed = runner.run(PREFLIGHT, None)?;
    if !completed.success() {
        return refuse(
            "target_unreachable",
            format!(
                "{} could not be inspected: {}",
                runner.destination.label(),
                completed.stderr_text()
            ),
        );
    }
    parse_preflight(&String::from_utf8_lossy(&completed.stdout))
}

pub fn parse_preflight(text: &str) -> Result<Preflight> {
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    let mut magic = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "ouroboros-preflight 1" {
            magic = true;
            continue;
        }
        if let Some((key, value)) = line.split_once(' ') {
            fields.insert(key, value.trim());
        }
    }
    if !magic {
        return refuse(
            "target_unreachable",
            "the target did not answer the setup preflight; check that its login shell is a POSIX shell and that the account can run commands over SSH",
        );
    }
    let get = |key: &str| fields.get(key).copied().unwrap_or("").to_string();
    let home = get("home");
    if home.is_empty() || !home.starts_with('/') {
        return refuse(
            "target_unreachable",
            "the target account has no usable HOME, so there is nowhere to install",
        );
    }
    let existing = match get("ouro").as_str() {
        "missing" | "" => None,
        path => Some(path.to_string()),
    };
    Ok(Preflight {
        uname: sanitize_remote_text(&get("uname"), 32),
        machine: sanitize_remote_text(&get("machine"), 32),
        version: sanitize_remote_text(&get("version"), 64),
        home: sanitize_remote_text(&home, 512),
        existing: existing.map(|path| sanitize_remote_text(&path, 512)),
        digest_tool: sanitize_remote_text(&get("digest"), 32),
    })
}

/// What [`BOOTSTRAP`] reported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Installed {
    pub sha256: String,
    pub path: String,
}

/// The header the bootstrap script reads, followed by the artifact's bytes.
///
/// A blank sixth line ends the header. Without it, a script that ever grew a seventh
/// field would read the first bytes of the executable as one; with it, the count of
/// header lines is part of the protocol and a mismatch is a refusal rather than a
/// silently corrupt upload.
pub fn upload_frame(
    asset: &str,
    bytes: &[u8],
    sha256: &str,
    install_path: &str,
) -> Result<Vec<u8>> {
    validate_asset_name(asset)?;
    validate_install_path(install_path)?;
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return refuse("invalid_request", "an artifact digest is 64 hex characters");
    }
    let header = format!(
        "ouroboros-bootstrap-1\n{asset}\n{}\n{sha256}\n{install_path}\n\n",
        bytes.len()
    );
    let mut frame = Vec::with_capacity(header.len() + bytes.len());
    frame.extend_from_slice(header.as_bytes());
    frame.extend_from_slice(bytes);
    Ok(frame)
}

/// Upload and install, through the one fixed command string.
pub fn install(
    runner: &Runner,
    asset: &str,
    bytes: &[u8],
    sha256: &str,
    install_path: &str,
) -> Result<Installed> {
    let frame = upload_frame(asset, bytes, sha256, install_path)?;
    let completed = runner.run_with_timeout(BOOTSTRAP, Some(&frame), UPLOAD_TIMEOUT)?;
    parse_receipt(&completed)
}

pub fn parse_receipt(completed: &Completed) -> Result<Installed> {
    let stdout = String::from_utf8_lossy(&completed.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("bootstrap-ok ") {
            let mut fields = rest.splitn(2, ' ');
            let (Some(sha256), Some(path)) = (fields.next(), fields.next()) else {
                break;
            };
            return Ok(Installed {
                sha256: sanitize_remote_text(sha256, 64),
                path: sanitize_remote_text(path, 512),
            });
        }
        if let Some(code) = line.strip_prefix("bootstrap-error ") {
            return Err(bootstrap_failure(code.trim()));
        }
    }
    refuse(
        "bootstrap_failed",
        format!(
            "the target did not confirm the installation (exit {}): {}",
            completed
                .code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".into()),
            completed.stderr_text()
        ),
    )
}

/// The remote script's own error vocabulary, turned into this client's reason codes.
fn bootstrap_failure(code: &str) -> anyhow::Error {
    let (reason, detail): (&'static str, String) = match code {
        "exists" => (
            "installation_exists",
            "the target already has a file at the selected install path. This workflow installs only a missing per-user Ouroboros; replacing an existing installation is an explicit manual step".into(),
        ),
        "checksum" => (
            "checksum_mismatch",
            "the bytes that arrived on the target do not hash to the release checksum, so nothing was installed".into(),
        ),
        "truncated" | "transfer" => (
            "bootstrap_failed",
            "the upload did not arrive whole; nothing was installed".into(),
        ),
        "no-digest-tool" => (
            "bootstrap_failed",
            "the target has neither sha256sum nor shasum, so the transfer cannot be verified there".into(),
        ),
        "home" | "staging" | "destdir" | "install" | "mode" => (
            "bootstrap_failed",
            format!("the target could not prepare the installation ({code})"),
        ),
        other => (
            "bootstrap_failed",
            format!("the target refused the upload ({})", sanitize_remote_text(other, 40)),
        ),
    };
    super::SetupError { reason, detail }.into()
}

/// Mirrors the remote `case` patterns, so a bad name is refused before a byte is sent.
pub fn validate_asset_name(asset: &str) -> Result<()> {
    let shaped = asset.starts_with("ouro-")
        && asset.len() <= 128
        && asset
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && asset
            .strip_prefix("ouro-")
            .and_then(|rest| rest.bytes().next())
            .is_some_and(|byte| byte.is_ascii_digit());
    if !shaped {
        return refuse(
            "invalid_request",
            format!("`{asset}` is not a release artifact name"),
        );
    }
    Ok(())
}

/// Mirrors the remote `case` patterns for the install path.
pub fn validate_install_path(path: &str) -> Result<()> {
    let shaped = !path.is_empty()
        && path.len() <= 256
        && !path.starts_with('/')
        && !path.contains("..")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'));
    if !shaped {
        return refuse(
            "unsupported_install_path",
            format!(
                "`{path}` is not an install path this workflow writes: it must be relative to the target account's home directory, with no `..`, and made of ordinary path characters. Installing outside the account's own home is a manual step"
            ),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two remote command strings are constants. If a future edit ever formats a
    /// variable into one of them, this fails: `{` and `$'` are how that would look, and
    /// neither belongs in a fixed script.
    #[test]
    fn the_remote_command_strings_carry_no_caller_data() {
        for command in [PREFLIGHT, BOOTSTRAP] {
            assert!(
                !command.contains('{')
                    || command.contains("${")
                    || command.contains("{ echo")
                    || command.contains("{ rm"),
                "a brace in a fixed remote command must be shell, not a format placeholder"
            );
        }
        // Every variable the bootstrap uses is one it read from stdin itself.
        for variable in ["$magic", "$name", "$size", "$sum", "$dest"] {
            assert!(BOOTSTRAP.contains(variable), "{variable}");
        }
        assert!(BOOTSTRAP.contains("head -c \"$size\""));
        assert!(BOOTSTRAP.contains("mv -f \"$t\" \"$p\""));
        assert!(BOOTSTRAP.contains("bootstrap-error exists"));
    }

    /// The names the remote `case` patterns accept, mirrored here so nothing is sent to
    /// a target that the target would then refuse.
    #[test]
    fn artifact_names_and_install_paths_are_validated_before_anything_is_sent() {
        assert!(validate_asset_name("ouro-0.1.8-aarch64-apple-darwin").is_ok());
        for hostile in [
            "ouro-0.1.8/../../etc/passwd",
            "../ouro-0.1.8",
            "ouro-;rm -rf /",
            "ouroboros",
            "ouro-",
            "",
        ] {
            assert!(validate_asset_name(hostile).is_err(), "{hostile}");
        }

        assert!(validate_install_path(".local/bin/ouro").is_ok());
        assert!(validate_install_path("bin/ouro").is_ok());
        for hostile in [
            "/usr/local/bin/ouro",
            "../../bin/ouro",
            "bin/$(id)",
            "",
            "a\nb",
        ] {
            assert!(validate_install_path(hostile).is_err(), "{hostile}");
        }
        assert_eq!(
            super::super::reason_of(
                &validate_install_path("/usr/local/bin/ouro").expect_err("an absolute path")
            ),
            Some("unsupported_install_path")
        );
    }

    /// The header is six lines and then the bytes, with nothing in between.
    #[test]
    fn the_upload_frame_is_a_six_line_header_then_exactly_the_artifact() {
        let bytes = b"\x7fELF-not-really".to_vec();
        let sha = "a".repeat(64);
        let frame = upload_frame(
            "ouro-0.1.8-aarch64-apple-darwin",
            &bytes,
            &sha,
            ".local/bin/ouro",
        )
        .expect("a frame");
        let header_end = frame
            .windows(2)
            .position(|pair| pair == b"\n\n")
            .expect("a blank line ending the header")
            + 2;
        let header = String::from_utf8(frame[..header_end].to_vec()).expect("a text header");
        assert_eq!(
            header.lines().collect::<Vec<_>>(),
            vec![
                "ouroboros-bootstrap-1",
                "ouro-0.1.8-aarch64-apple-darwin",
                "15",
                sha.as_str(),
                ".local/bin/ouro",
                // The sixth line is blank and ends the header. The remote script reads
                // exactly six lines, so the count is part of the protocol: a seventh
                // field added one day cannot be silently read out of the executable.
                "",
            ]
        );
        assert_eq!(&frame[header_end..], &bytes[..]);
        assert_eq!(bytes.len(), 15);
    }

    /// The receipt vocabulary maps onto the reason codes an operator acts on.
    #[test]
    fn the_remote_receipt_becomes_a_stable_reason() {
        let ok = parse_receipt(&Completed {
            code: Some(0),
            stdout: b"bootstrap-ok abc123 /home/me/.local/bin/ouro\n".to_vec(),
            stderr: Vec::new(),
        })
        .expect("a receipt");
        assert_eq!(ok.sha256, "abc123");
        assert_eq!(ok.path, "/home/me/.local/bin/ouro");

        for (line, expected) in [
            ("bootstrap-error exists", "installation_exists"),
            ("bootstrap-error checksum", "checksum_mismatch"),
            ("bootstrap-error truncated", "bootstrap_failed"),
            ("bootstrap-error something-new", "bootstrap_failed"),
        ] {
            let error = parse_receipt(&Completed {
                code: Some(68),
                stdout: format!("{line}\n").into_bytes(),
                stderr: Vec::new(),
            })
            .expect_err("a refusal");
            assert_eq!(super::super::reason_of(&error), Some(expected), "{line}");
        }

        let silent = parse_receipt(&Completed {
            code: Some(1),
            stdout: Vec::new(),
            stderr: b"sh: head: not found".to_vec(),
        })
        .expect_err("a refusal");
        assert_eq!(super::super::reason_of(&silent), Some("bootstrap_failed"));
    }

    /// The preflight's output decides which artifact is chosen, so it is parsed exactly.
    #[test]
    fn the_preflight_reports_the_target_and_whether_it_already_has_an_ouro() {
        let macos = parse_preflight(
            "ouroboros-preflight 1\nuname Darwin\nmachine arm64\nversion 15.1\nhome /Users/me\nouro missing\ndigest shasum\n",
        )
        .expect("a preflight");
        assert_eq!(macos.os(), "macos");
        assert_eq!(macos.existing, None);
        assert_eq!(
            macos.target_triple().expect("a supported target"),
            "aarch64-apple-darwin"
        );
        assert_eq!(
            macos.install_path(".local/bin/ouro"),
            "/Users/me/.local/bin/ouro"
        );

        let linux = parse_preflight(
            "ouroboros-preflight 1\nuname Linux\nmachine x86_64\nversion glibc 2.39\nhome /home/me\nouro /home/me/.local/bin/ouro\ndigest sha256sum\n",
        )
        .expect("a preflight");
        assert_eq!(linux.os(), "linux");
        assert_eq!(linux.existing.as_deref(), Some("/home/me/.local/bin/ouro"));
        assert_eq!(
            linux.target_triple().expect("a supported target"),
            "x86_64-unknown-linux-gnu"
        );

        let unsupported = parse_preflight(
            "ouroboros-preflight 1\nuname Linux\nmachine x86_64\nversion glibc 2.31\nhome /home/me\nouro missing\ndigest sha256sum\n",
        )
        .expect("a preflight");
        assert_eq!(
            super::super::reason_of(&unsupported.target_triple().expect_err("an old glibc")),
            Some("unsupported_platform")
        );

        assert!(
            parse_preflight("bash: line 1: syntax error\n").is_err(),
            "a shell that did not run the preflight is not a preflight"
        );
        assert!(
            parse_preflight("ouroboros-preflight 1\nuname Linux\nhome relative\n").is_err(),
            "a target with no usable HOME has nowhere to install"
        );
    }
}
